from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.database import get_db
from app.auth import get_current_user
from app.crypto_engine import run_scenarios_benchmark

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/benchmark", response_class=HTMLResponse)
async def benchmark_page(
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Halaman Audit Performa Kriptografi:
    Menjalankan pengujian 4 skenario tolok ukur kriptografi administrasi bansos
    (AES-256-CBC, DES-CBC, RC4) sesuai referensi UI admin-panel-kriptografi.jpeg.
    """
    user = get_current_user(request, db)

    # Jalankan benchmark 4 skenario
    scenarios, last_tested = run_scenarios_benchmark()

    return templates.TemplateResponse(
        request=request,
        name="benchmark.html",
        context={
            "current_user": user,
            "scenarios": scenarios,
            "last_tested": last_tested,
        }
    )

