import secrets
from fastapi import APIRouter, Request, Depends, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User
from app.auth import (
    verify_password,
    get_password_hash,
    create_access_token,
    get_current_user,
    COOKIE_NAME,
)

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/", response_class=HTMLResponse)
async def home(request: Request, db: Session = Depends(get_db)):
    """Redirect root ke dashboard sesuai role jika sudah login, atau ke /auth/login."""
    user = get_current_user(request, db)
    if user:
        if user.role == "verifikator":
            return RedirectResponse(url="/verifier/dashboard", status_code=status.HTTP_303_SEE_OTHER)
        return RedirectResponse(url="/kpm/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse(url="/auth/login", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/auth/login", response_class=HTMLResponse)
async def login_page(request: Request, db: Session = Depends(get_db)):
    """Tampilkan halaman login."""
    user = get_current_user(request, db)
    if user:
        if user.role == "verifikator":
            return RedirectResponse(url="/verifier/dashboard", status_code=status.HTTP_303_SEE_OTHER)
        return RedirectResponse(url="/kpm/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request=request, name="login.html", context={"current_user": None})


@router.post("/auth/login")
async def login_action(
    request: Request,
    nik: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    """Proses autentikasi login dan set signed HTTP-only cookie."""
    nik = nik.strip()
    if len(nik) != 16 or not nik.isdigit():
        return RedirectResponse(
            url="/auth/login?error=NIK+harus+berupa+16+digit+angka.",
            status_code=status.HTTP_303_SEE_OTHER
        )
    user = db.query(User).filter(User.nik == nik).first()

    if not user or not verify_password(password, user.hashed_password):
        return RedirectResponse(
            url="/auth/login?error=NIK+atau+Password+salah.+Silakan+coba+kembali.",
            status_code=status.HTTP_303_SEE_OTHER
        )

    # Buat JWT access token
    token = create_access_token({
        "sub": user.nik,
        "user_id": user.id,
        "role": user.role,
        "nama": user.nama
    })

    # Redirect target berdasarkan role
    target_url = "/verifier/dashboard" if user.role == "verifikator" else "/kpm/dashboard"
    response = RedirectResponse(url=target_url, status_code=status.HTTP_303_SEE_OTHER)

    # Set HTTP-only Cookie
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        max_age=86400,
        samesite="lax",
    )
    return response


@router.get("/auth/register", response_class=HTMLResponse)
async def register_page(request: Request, db: Session = Depends(get_db)):
    """Tampilkan halaman registrasi KPM."""
    user = get_current_user(request, db)
    if user:
        return RedirectResponse(url="/kpm/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request=request, name="register.html", context={"current_user": None})


@router.post("/auth/register")
async def register_action(
    request: Request,
    nik: str = Form(...),
    nama: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    db: Session = Depends(get_db)
):
    """Proses registrasi akun KPM warga baru dengan pembuatan salt PBKDF2."""
    nik = nik.strip()
    nama = nama.strip()

    if len(nik) != 16 or not nik.isdigit():
        return RedirectResponse(
            url="/auth/register?error=NIK+harus+berupa+16+digit+angka.",
            status_code=status.HTTP_303_SEE_OTHER
        )

    if password != password_confirm:
        return RedirectResponse(
            url="/auth/register?error=Konfirmasi+password+tidak+cocok.",
            status_code=status.HTTP_303_SEE_OTHER
        )

    if len(password) < 6:
        return RedirectResponse(
            url="/auth/register?error=Password+minimal+6+karakter.",
            status_code=status.HTTP_303_SEE_OTHER
        )

    # Cek apakah NIK sudah terdaftar
    existing = db.query(User).filter(User.nik == nik).first()
    if existing:
        return RedirectResponse(
            url="/auth/register?error=NIK+tersebut+sudah+terdaftar.+Silakan+masuk.",
            status_code=status.HTTP_303_SEE_OTHER
        )

    # Generate 16-byte random salt unik untuk PBKDF2 key derivation
    kdf_salt = secrets.token_hex(16)
    hashed_pwd = get_password_hash(password)

    new_user = User(
        nik=nik,
        nama=nama,
        hashed_password=hashed_pwd,
        kdf_salt=kdf_salt,
        role="kpm"
    )
    db.add(new_user)
    db.commit()

    return RedirectResponse(
        url="/auth/login?success=Akun+KPM+berhasil+didaftarkan.+Silakan+masuk+dengan+NIK+dan+Password.",
        status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/auth/logout")
async def logout():
    """Hapus session cookie dan redirect ke halaman login."""
    response = RedirectResponse(url="/auth/login?msg=Anda+telah+berhasil+keluar.", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(COOKIE_NAME)
    return response
