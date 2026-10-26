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


@router.get("/dashboard", response_class=HTMLResponse)
async def verifier_dashboard(
    request: Request,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Dashboard Verifikator:
    - Menampilkan ringkasan metrik (Total, Pending, Approved, Rejected).
    - Menampilkan tabel seluruh permohonan warga.
    """
    user = check_verifier_user(request, db)

    # Filter status jika dipilih
    query = db.query(Application).options(
        joinedload(Application.user),
        joinedload(Application.documents)
    )
    current_status = status if status in ["Pending", "Approved", "Rejected"] else None
    if current_status:
        query = query.filter(Application.status == current_status)

    applications = query.order_by(Application.created_at.desc()).all()

    # Hitung metrik ringkasan
    total = db.query(Application).count()
    pending = db.query(Application).filter(Application.status == "Pending").count()
    approved = db.query(Application).filter(Application.status == "Approved").count()
    rejected = db.query(Application).filter(Application.status == "Rejected").count()

    stats = {
        "total": total,
        "pending": pending,
        "approved": approved,
        "rejected": rejected,
    }

    return templates.TemplateResponse(
        request=request,
        name="verifier_dashboard.html",
        context={
            "current_user": user,
            "applications": applications,
            "stats": stats,
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

    return templates.TemplateResponse(
        request=request,
        name="verifier_detail.html",
        context={
            "current_user": user,
            "application": application,
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
    user = check_verifier_user(request, db)

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
    Menggunakan kunci KDF pengguna pemilik berkas dan IV yang tersimpan di DB.
    """
    user = check_verifier_user(request, db)

    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Dokumen tidak ditemukan.")

    # Dapatkan pemilik berkas untuk derivasi kunci KDF
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
            key = get_user_cipher_key(owner_user.hashed_password, owner_user.kdf_salt, "AES-256-CBC")
            iv = bytes.fromhex(doc.iv_hex)
            plain_bytes = decrypt_aes_256_cbc(ciphertext, key, iv)
        elif "DES" in doc.cipher_used:
            key = get_user_cipher_key(owner_user.hashed_password, owner_user.kdf_salt, "DES-CBC")
            iv = bytes.fromhex(doc.iv_hex)
            plain_bytes = decrypt_des_cbc(ciphertext, key, iv)
        elif "RC4" in doc.cipher_used:
            key = get_user_cipher_key(owner_user.hashed_password, owner_user.kdf_salt, "RC4")
            plain_bytes = decrypt_rc4(ciphertext, key)
        else:
            raise ValueError(f"Cipher {doc.cipher_used} tidak dikenal.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Gagal mendekripsi berkas: {str(e)}")

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

    total = db.query(Application).count()
    pending = db.query(Application).filter(Application.status == "Pending").count()
    approved = db.query(Application).filter(Application.status == "Approved").count()
    rejected = db.query(Application).filter(Application.status == "Rejected").count()

    total_docs = sum(len(a.documents) for a in approved_apps)

    return templates.TemplateResponse(
        request=request,
        name="verifier_keluarga.html",
        context={
            "current_user": user,
            "approved_apps": approved_apps,
            "total_docs": total_docs,
            "stats": {"total": total, "pending": pending, "approved": approved, "rejected": rejected},
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
        }
    )


# ─────────────────────────────────────────────────────────────
# HALAMAN: BUKU ALAMAT RT/RW
# ─────────────────────────────────────────────────────────────
@router.get("/alamat", response_class=HTMLResponse)
async def verifier_alamat(request: Request, db: Session = Depends(get_db)):
    """Peta distribusi warga pemohon berdasarkan keterangan/domisili."""
    user = check_verifier_user(request, db)

    all_apps = (
        db.query(Application)
        .options(joinedload(Application.user))
        .order_by(Application.created_at.desc())
        .all()
    )

    # Kelompokkan berdasarkan keterangan (digunakan sebagai "alamat/wilayah")
    wilayah_map: dict[str, list] = {}
    for app in all_apps:
        key = (app.keterangan or "Tidak Diketahui").strip()[:60]
        wilayah_map.setdefault(key, []).append(app)

    return templates.TemplateResponse(
        request=request,
        name="verifier_alamat.html",
        context={
            "current_user": user,
            "wilayah_list": wilayah_map,
        }
    )


# ─────────────────────────────────────────────────────────────
# HALAMAN: AKUN PETUGAS
# ─────────────────────────────────────────────────────────────
@router.get("/akun", response_class=HTMLResponse)
async def verifier_akun(request: Request, db: Session = Depends(get_db)):
    """Profil dan informasi keamanan akun verifikator yang sedang login."""
    user = check_verifier_user(request, db)

    total = db.query(Application).count()
    approved = db.query(Application).filter(Application.status == "Approved").count()
    rejected = db.query(Application).filter(Application.status == "Rejected").count()

    return templates.TemplateResponse(
        request=request,
        name="verifier_akun.html",
        context={
            "current_user": user,
            "stats": {"total": total, "approved": approved, "rejected": rejected},
        }
    )

