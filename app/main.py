import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, Response
from fastapi.exception_handlers import http_exception_handler
from starlette.exceptions import HTTPException as StarletteHTTPException
from app.database import init_db, BASE_DIR
from app.routes import auth_routes, kpm_routes, verifier_routes, benchmark_routes

# Pastikan folder penyimpanan file .enc tersedia
STORAGE_ENCRYPTED_DIR = os.path.join(BASE_DIR, "storage", "encrypted")
os.makedirs(STORAGE_ENCRYPTED_DIR, exist_ok=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Inisialisasi tabel SQLite & seeding akun verifikator awal
    init_db()
    yield


app = FastAPI(
    title="Sigapp - Sistem Verifikasi Bansos Terenkripsi",
    description="Aplikasi Monolitik FastAPI dengan Enkripsi AES-256-CBC, DES-CBC, RC4 & PBKDF2 untuk Keamanan Informasi",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """Mencegah 404 / 500 saat browser meminta favicon."""
    return Response(status_code=204)


# Exception handler untuk menangani redirect HTTP 303 secara bersih pada template SSR
@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 303:
        target = exc.headers.get("Location", "/auth/login")
        return RedirectResponse(url=target, status_code=303)
    return await http_exception_handler(request, exc)


# Mount seluruh router
app.include_router(auth_routes.router)
app.include_router(kpm_routes.router)
app.include_router(verifier_routes.router)
app.include_router(benchmark_routes.router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
