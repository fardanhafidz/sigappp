import os
import uuid
import secrets
import io
from datetime import datetime
from fastapi import APIRouter, Request, Depends, Form, File, UploadFile, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session, joinedload
from app.database import get_db, BASE_DIR
from app.models import User, Application, Document
from app.auth import get_current_user
from app.crypto_engine import (
    get_user_cipher_key,
    encrypt_aes_256_cbc,
    decrypt_aes_256_cbc,
    encrypt_des_cbc,
    decrypt_des_cbc,
    encrypt_rc4,
    decrypt_rc4,
)

router = APIRouter(prefix="/kpm")
templates = Jinja2Templates(directory="app/templates")

STORAGE_ENCRYPTED_DIR = os.path.join(BASE_DIR, "storage", "encrypted")
os.makedirs(STORAGE_ENCRYPTED_DIR, exist_ok=True)


def check_kpm_user(request: Request, db: Session) -> User:
    """Helper untuk memverifikasi autentikasi KPM."""
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/auth/login?msg=Silakan+masuk+terlebih+dahulu"}
        )
    if user.role != "kpm":
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/verifier/dashboard?error=Akses+khusus+KPM"}
        )
    return user


@router.get("/dashboard", response_class=HTMLResponse)
async def kpm_dashboard(request: Request, db: Session = Depends(get_db)):
    """Menampilkan dashboard warga KPM dengan daftar pengajuan dan berkas miliknya."""
    user = check_kpm_user(request, db)
    applications = (
        db.query(Application)
        .options(joinedload(Application.documents))
        .filter(Application.user_id == user.id)
        .order_by(Application.created_at.desc())
        .all()
    )
    return templates.TemplateResponse(
        request=request,
        name="kpm_dashboard.html",
        context={"current_user": user, "applications": applications}
    )


@router.get("/apply", response_class=HTMLResponse)
async def apply_form(request: Request, db: Session = Depends(get_db)):
    """Formulir pengajuan bansos baru atau tampilan pengajuan yang sudah ada."""
    user = check_kpm_user(request, db)
    existing_app = (
        db.query(Application)
        .options(joinedload(Application.documents))
        .filter(Application.user_id == user.id)
        .order_by(Application.created_at.desc())
        .first()
    )
    return templates.TemplateResponse(
        request=request,
        name="apply_form.html",
        context={
            "current_user": user,
            "existing_app": existing_app,
        }
    )


@router.post("/withdraw")
@router.post("/application/{app_id}/delete")
async def withdraw_application(
    request: Request,
    app_id: int | None = None,
    db: Session = Depends(get_db)
):
    """
    Menarik atau menghapus berkas pengajuan warga:
    1. Memverifikasi kepemilikan berkas pengajuan.
    2. Menghapus seluruh berkas terenkripsi .enc dari disk.
    3. Menghapus record Dokumen dan Pengajuan dari database.
    """
    user = check_kpm_user(request, db)
    query = (
        db.query(Application)
        .options(joinedload(Application.documents))
        .filter(Application.user_id == user.id)
    )
    if app_id:
        query = query.filter(Application.id == app_id)
    app = query.order_by(Application.created_at.desc()).first()

    if not app:
        return RedirectResponse(
            url="/kpm/apply?error=Tidak+ada+berkas+pengajuan+aktif+untuk+ditarik.",
            status_code=status.HTTP_303_SEE_OTHER
        )

    # Hapus file ciphertext dari disk fisik
    for doc in app.documents:
        abs_path = os.path.join(BASE_DIR, doc.file_path)
        if os.path.exists(abs_path):
            try:
                os.remove(abs_path)
            except Exception:
                pass

    nomor = app.nomor_pengajuan
    db.delete(app)
    db.commit()

    return RedirectResponse(
        url=f"/kpm/apply?success=Pengajuan+{nomor}+berhasil+ditarik.+Anda+sekarang+dapat+mengisi+formulir+pengajuan+baru.",
        status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/apply")
async def submit_application(
    request: Request,
    keterangan: str = Form(""),
    file_ktp_kk: UploadFile = File(...),
    file_slip_gaji: UploadFile = File(...),
    file_berita_acara: UploadFile = File(...),
    file_video_rumah: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """
    Memproses formulir bansos:
    1. Memastikan pengguna belum memiliki berkas pengajuan aktif.
    2. Membaca bytes berkas asli.
    3. Menurunkan kunci enkripsi dari password pengguna via PBKDF2-HMAC-SHA256.
    4. Mengenkripsi berkas dengan cipher yang ditentukan:
       - KTP/KK: AES-256-CBC
       - Slip Gaji: AES-256-CBC
       - Berita Acara: DES-CBC
       - Video Rumah: RC4
    5. Menyimpan ciphertext biner ke storage/encrypted/{file_id}.enc.
    6. Menyimpan metadata ke SQLite.
    """
    user = check_kpm_user(request, db)

    # Pastikan pengguna belum memiliki pengajuan aktif
    existing = db.query(Application).filter(Application.user_id == user.id).first()
    if existing:
        return RedirectResponse(
            url="/kpm/apply?error=Anda+sudah+memiliki+pengajuan+aktif.+Tarik+atau+hapus+pengajuan+terlebih+dahulu+untuk+membuat+yang+baru.",
            status_code=status.HTTP_303_SEE_OTHER
        )

    # Validasi kelengkapan berkas
    # Batas ukuran file (dalam bytes): KTP 2MB, SKTM 5MB, Berita Acara 10MB, Video 100MB
    MAX_SIZES_MB = {
        "file_ktp_kk": 2,
        "file_slip_gaji": 5,
        "file_berita_acara": 10,
        "file_video_rumah": 100,
    }
    uploaded_files = [
        (file_ktp_kk, "ktp_kk", "Pindaian KTP / KK", "AES-256-CBC"),
        (file_slip_gaji, "slip_gaji", "Slip Gaji / SKTM", "AES-256-CBC"),
        (file_berita_acara, "berita_acara", "Berita Acara Survei", "DES-CBC"),
        (file_video_rumah, "video_rumah", "Video Kondisi Rumah", "RC4"),
    ]

    for f, _, label, _ in uploaded_files:
        if not f.filename:
            return RedirectResponse(
                url=f"/kpm/apply?error=Berkas+{label}+wajib+diunggah.",
                status_code=status.HTTP_303_SEE_OTHER
            )

    # Baca dan validasi ukuran file sebelum memproses enkripsi
    file_bytes_map = {}
    for f, category, label, cipher_type in uploaded_files:
        raw = await f.read()
        max_bytes = MAX_SIZES_MB[f.field_name if hasattr(f, 'field_name') else category] * 1024 * 1024 if category in MAX_SIZES_MB else None
        # Cari max size berdasarkan nama field input
        field_max_mb = None
        if category == "ktp_kk":
            field_max_mb = MAX_SIZES_MB["file_ktp_kk"]
        elif category == "slip_gaji":
            field_max_mb = MAX_SIZES_MB["file_slip_gaji"]
        elif category == "berita_acara":
            field_max_mb = MAX_SIZES_MB["file_berita_acara"]
        elif category == "video_rumah":
            field_max_mb = MAX_SIZES_MB["file_video_rumah"]

        if field_max_mb and len(raw) > field_max_mb * 1024 * 1024:
            actual_mb = round(len(raw) / 1024 / 1024, 1)
            return RedirectResponse(
                url=f"/kpm/apply?error=Berkas+{label}+melebihi+batas+{field_max_mb}MB+(ukuran+file:+{actual_mb}MB).",
                status_code=status.HTTP_303_SEE_OTHER
            )
        file_bytes_map[category] = raw

    # Buat record Application baru
    nomor_pengajuan = f"BANSOS-{datetime.utcnow().strftime('%Y%m%d')}-{secrets.token_hex(3).upper()}"
    new_app = Application(
        nomor_pengajuan=nomor_pengajuan,
        user_id=user.id,
        keterangan=keterangan.strip(),
        status="Pending",
    )
    db.add(new_app)
    db.flush()  # Dapatkan new_app.id

    # Proses enkripsi untuk masing-masing berkas
    for file_obj, category, label, cipher_type in uploaded_files:
        plain_bytes = file_bytes_map[category]  # gunakan bytes yang sudah dibaca saat validasi
        file_id = str(uuid.uuid4())
        iv_hex = None

        if cipher_type == "AES-256-CBC":
            key = get_user_cipher_key(user.hashed_password, user.kdf_salt, "AES-256-CBC")
            ciphertext, iv = encrypt_aes_256_cbc(plain_bytes, key)
            iv_hex = iv.hex()
        elif cipher_type == "DES-CBC":
            key = get_user_cipher_key(user.hashed_password, user.kdf_salt, "DES-CBC")
            ciphertext, iv = encrypt_des_cbc(plain_bytes, key)
            iv_hex = iv.hex()
        elif cipher_type == "RC4":
            key = get_user_cipher_key(user.hashed_password, user.kdf_salt, "RC4")
            ciphertext = encrypt_rc4(plain_bytes, key)
            iv_hex = None
        else:
            raise ValueError(f"Cipher {cipher_type} tidak didukung.")

        # Simpan file biner .enc ke disk
        disk_filename = f"{file_id}.enc"
        dest_path = os.path.join(STORAGE_ENCRYPTED_DIR, disk_filename)
        with open(dest_path, "wb") as f_out:
            f_out.write(ciphertext)

        # Simpan metadata berkas ke database
        doc = Document(
            file_id=file_id,
            application_id=new_app.id,
            user_id=user.id,
            category=category,
            category_label=label,
            original_filename=file_obj.filename,
            mime_type=file_obj.content_type or "application/octet-stream",
            cipher_used=cipher_type,
            iv_hex=iv_hex,
            file_size=len(plain_bytes),
            file_path=os.path.join("storage", "encrypted", disk_filename),
        )
        db.add(doc)

    db.commit()

    return RedirectResponse(
        url=f"/kpm/dashboard?success=Pengajuan+{nomor_pengajuan}+berhasil+dikirim.+Seluruh+4+berkas+telah+dienkripsi+secara+lossless.",
        status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/download/{doc_id}")
async def download_kpm_file(
    doc_id: int,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Unduh berkas milik KPM sendiri dengan dekripsi on-the-fly:
    Membaca biner .enc dari disk, mendekripsi dengan kunci KDF pengguna,
    lalu mengirimkan payload asli dengan StreamingResponse.
    """
    user = check_kpm_user(request, db)

    doc = db.query(Document).filter(Document.id == doc_id, Document.user_id == user.id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Dokumen tidak ditemukan atau akses ditolak.")

    abs_path = os.path.join(BASE_DIR, doc.file_path)
    if not os.path.exists(abs_path):
        raise HTTPException(status_code=404, detail="File terenkripsi pada disk tidak ditemukan.")

    with open(abs_path, "rb") as f_in:
        ciphertext = f_in.read()

    # Dekripsi on-the-fly
    try:
        if "AES" in doc.cipher_used:
            key = get_user_cipher_key(user.hashed_password, user.kdf_salt, "AES-256-CBC")
            iv = bytes.fromhex(doc.iv_hex)
            plain_bytes = decrypt_aes_256_cbc(ciphertext, key, iv)
        elif "DES" in doc.cipher_used:
            key = get_user_cipher_key(user.hashed_password, user.kdf_salt, "DES-CBC")
            iv = bytes.fromhex(doc.iv_hex)
            plain_bytes = decrypt_des_cbc(ciphertext, key, iv)
        elif "RC4" in doc.cipher_used:
            key = get_user_cipher_key(user.hashed_password, user.kdf_salt, "RC4")
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
