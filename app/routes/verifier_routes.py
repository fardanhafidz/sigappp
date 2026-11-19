import os
import io
from typing import Optional
from fastapi import APIRouter, Request, Depends, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session, joinedload
from app.database import get_db, BASE_DIR
from app.models import User, Application, Document
from app.auth import get_current_user
from app.crypto_engine import (
    get_user_cipher_key,
    decrypt_aes_256_cbc,
    decrypt_des_cbc,
    decrypt_rc4,
    decrypt_text_aes_256_cbc,
    verify_sha256,
)

router = APIRouter(prefix="/verifier")
templates = Jinja2Templates(directory="app/templates")


def check_verifier_user(request: Request, db: Session) -> User:
    """Helper untuk memverifikasi autentikasi Verifikator."""
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/auth/login?msg=Silakan+masuk+sebagai+petugas"}
        )
    if user.role != "verifikator":
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/kpm/dashboard?error=Akses+khusus+petugas+verifikator"}
        )
    return user


def _get_stats(db: Session) -> dict[str, int]:
    """Menghitung metrik ringkasan antrean untuk dashboard dan badge sidebar."""
    return {
        "total": db.query(Application).count(),
        "pending": db.query(Application).filter(Application.status == "Pending").count(),
        "approved": db.query(Application).filter(Application.status == "Approved").count(),
        "rejected": db.query(Application).filter(Application.status == "Rejected").count(),
    }


def _attach_plain_keterangan(app: Application) -> None:
    """Mendekripsi alamat/keterangan milik pemilik pengajuan ke atribut transient."""
    owner = app.user
    if not owner:
        app.keterangan_plain = app.keterangan or ""
        return
    aes_key = get_user_cipher_key(owner.nik, owner.kdf_salt, "AES-256-CBC")
    app.keterangan_plain = decrypt_text_aes_256_cbc(app.keterangan, aes_key)


@router.get("/dashboard", response_class=HTMLResponse)
async def verifier_dashboard(
    request: Request,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Dashboard Verifikator:
    - Menampilkan ringkasan metrik (Total, Pending, Approved, Rejected).
    - Menampilkan tabel seluruh permohonan warga dengan alamat yang telah didekripsi.
    """
    user = check_verifier_user(request, db)

    query = db.query(Application).options(
        joinedload(Application.user),
        joinedload(Application.documents)
    )
    current_status = status if status in ["Pending", "Approved", "Rejected"] else None
    if current_status:
        query = query.filter(Application.status == current_status)

    applications = query.order_by(Application.created_at.desc()).all()
    for app in applications:
        _attach_plain_keterangan(app)

    return templates.TemplateResponse(
        request=request,
        name="verifier_dashboard.html",
        context={
            "current_user": user,
            "applications": applications,
            "stats": _get_stats(db),
            "current_status": current_status,
        }
    )


@router.get("/application/{app_id}", response_class=HTMLResponse)
async def verifier_application_detail(
    app_id: int,
    request: Request,
    db: Session = Depends(get_db)
):
    """Halaman detail permohonan warga untuk verifikasi faktual berkas terenkripsi."""
    user = check_verifier_user(request, db)

    application = (
        db.query(Application)
        .options(
            joinedload(Application.user),
            joinedload(Application.documents)
        )
        .filter(Application.id == app_id)
        .first()
    )
    if not application:
        raise HTTPException(status_code=404, detail="Pengajuan tidak ditemukan.")

    _attach_plain_keterangan(application)

    return templates.TemplateResponse(
        request=request,
        name="verifier_detail.html",
        context={
            "current_user": user,
            "application": application,
            "stats": _get_stats(db),
        }
    )


@router.post("/application/{app_id}/status")
async def update_application_status(
    app_id: int,
    request: Request,
    new_status: str = Form(..., alias="status"),
    verifikator_notes: str = Form(""),
    db: Session = Depends(get_db)
):
    """Memperbarui status pengajuan (Approved / Rejected / Pending) dan catatan verifikator."""
    check_verifier_user(request, db)

    application = db.query(Application).filter(Application.id == app_id).first()
    if not application:
        raise HTTPException(status_code=404, detail="Pengajuan tidak ditemukan.")

    if new_status not in ["Pending", "Approved", "Rejected"]:
        raise HTTPException(status_code=400, detail="Status tidak valid.")

    application.status = new_status
    application.verifikator_notes = verifikator_notes.strip()
    db.commit()

    return RedirectResponse(
        url=f"/verifier/application/{app_id}?success=Keputusan+verifikasi+berhasil+disimpan.+Status+kini:+{new_status}",
        status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/download/{doc_id}")
async def verifier_download_file(
    doc_id: int,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Unduh dan dekripsi berkas warga on-the-fly oleh Verifikator Dinsos:
    Menggunakan kunci KDF milik pemilik berkas, IV/nonce tersimpan, serta verifikasi SHA-256.
    """
    check_verifier_user(request, db)

    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Dokumen tidak ditemukan.")

    owner_user = doc.user
    if not owner_user:
        raise HTTPException(status_code=404, detail="Pemilik dokumen tidak ditemukan.")

    abs_path = os.path.join(BASE_DIR, doc.file_path)
    if not os.path.exists(abs_path):
        raise HTTPException(status_code=404, detail="File ciphertext pada disk tidak ditemukan.")

    with open(abs_path, "rb") as f_in:
        ciphertext = f_in.read()

    # Dekripsi on-the-fly
    try:
        if "AES" in doc.cipher_used:
            key = get_user_cipher_key(owner_user.nik, owner_user.kdf_salt, "AES-256-CBC")
            iv = bytes.fromhex(doc.iv_hex)
            plain_bytes = decrypt_aes_256_cbc(ciphertext, key, iv)
        elif "DES" in doc.cipher_used:
            key = get_user_cipher_key(owner_user.nik, owner_user.kdf_salt, "DES-CBC")
            iv = bytes.fromhex(doc.iv_hex)
            plain_bytes = decrypt_des_cbc(ciphertext, key, iv)
        elif "RC4" in doc.cipher_used:
            if not doc.iv_hex:
                raise ValueError("Nonce RC4 tidak ditemukan pada metadata dokumen.")
            key = get_user_cipher_key(owner_user.nik, owner_user.kdf_salt, "RC4")
            nonce = bytes.fromhex(doc.iv_hex)
            plain_bytes = decrypt_rc4(ciphertext, key, nonce)
        else:
            raise ValueError(f"Cipher {doc.cipher_used} tidak dikenal.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Gagal mendekripsi berkas: {str(e)}")

    if not verify_sha256(plain_bytes, doc.sha256_hash):
        raise HTTPException(
            status_code=500,
            detail="Verifikasi integritas SHA-256 gagal: berkas terenkripsi telah termodifikasi atau korup."
        )

    return StreamingResponse(
        io.BytesIO(plain_bytes),
        media_type=doc.mime_type,
        headers={
            "Content-Disposition": f'attachment; filename="{doc.original_filename}"'
        }
    )


# ─────────────────────────────────────────────────────────────
# HALAMAN: KELUARGA PENERIMA
# ─────────────────────────────────────────────────────────────
@router.get("/keluarga", response_class=HTMLResponse)
async def verifier_keluarga(request: Request, db: Session = Depends(get_db)):
    """Daftar semua KPM yang pengajuannya berstatus Approved."""
    user = check_verifier_user(request, db)

    approved_apps = (
        db.query(Application)
        .options(joinedload(Application.user), joinedload(Application.documents))
        .filter(Application.status == "Approved")
        .order_by(Application.updated_at.desc())
        .all()
    )
    for app in approved_apps:
        _attach_plain_keterangan(app)

    total_docs = sum(len(a.documents) for a in approved_apps)

    return templates.TemplateResponse(
        request=request,
        name="verifier_keluarga.html",
        context={
            "current_user": user,
            "approved_apps": approved_apps,
            "total_docs": total_docs,
            "stats": _get_stats(db),
        }
    )


# ─────────────────────────────────────────────────────────────
# HALAMAN: ARSIP BERKAS
# ─────────────────────────────────────────────────────────────
@router.get("/arsip", response_class=HTMLResponse)
async def verifier_arsip(request: Request, db: Session = Depends(get_db)):
    """Seluruh berkas terenkripsi yang pernah diunggah oleh warga."""
    user = check_verifier_user(request, db)

    documents = (
        db.query(Document)
        .options(
            joinedload(Document.user),
            joinedload(Document.application),
        )
        .order_by(Document.created_at.desc())
        .all()
    )

    aes_count = sum(1 for d in documents if "AES" in d.cipher_used)
    des_count = sum(1 for d in documents if "DES" in d.cipher_used)
    rc4_count = sum(1 for d in documents if "RC4" in d.cipher_used)

    return templates.TemplateResponse(
        request=request,
        name="verifier_arsip.html",
        context={
            "current_user": user,
            "documents": documents,
            "aes_count": aes_count,
            "des_count": des_count,
            "rc4_count": rc4_count,
            "stats": _get_stats(db),
        }
    )


# ─────────────────────────────────────────────────────────────
# HALAMAN: BUKU ALAMAT RT/RW
# ─────────────────────────────────────────────────────────────
@router.get("/alamat", response_class=HTMLResponse)
async def verifier_alamat(request: Request, db: Session = Depends(get_db)):
    """Peta distribusi warga pemohon berdasarkan domisili hasil dekripsi."""
    user = check_verifier_user(request, db)

    all_apps = (
        db.query(Application)
        .options(joinedload(Application.user))
        .order_by(Application.created_at.desc())
        .all()
    )

    wilayah_map: dict[str, list] = {}
    for app in all_apps:
        _attach_plain_keterangan(app)
        key = (app.keterangan_plain or "Tidak Diketahui").strip()[:60]
        wilayah_map.setdefault(key, []).append(app)

    return templates.TemplateResponse(
        request=request,
        name="verifier_alamat.html",
        context={
            "current_user": user,
            "wilayah_list": wilayah_map,
            "stats": _get_stats(db),
        }
    )


# ─────────────────────────────────────────────────────────────
# HALAMAN: AKUN PETUGAS
# ─────────────────────────────────────────────────────────────
@router.get("/akun", response_class=HTMLResponse)
async def verifier_akun(request: Request, db: Session = Depends(get_db)):
    """Profil dan informasi keamanan akun verifikator yang sedang login."""
    user = check_verifier_user(request, db)

    return templates.TemplateResponse(
        request=request,
        name="verifier_akun.html",
        context={
            "current_user": user,
            "stats": _get_stats(db),
        }
    )
