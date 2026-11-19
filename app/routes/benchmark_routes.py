from fastapi import APIRouter, Request, Depends, Query
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Application
from app.auth import get_current_user
from app.crypto_engine import benchmark_ciphers, run_bansos_scenarios_benchmark

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

ALLOWED_BENCHMARK_SIZES_KB = [100, 1024, 5120]


@router.get("/benchmark", response_class=HTMLResponse)
async def benchmark_page(
    request: Request,
    size_kb: int = Query(1024),
    db: Session = Depends(get_db)
):
    """
    Halaman Audit Performa Kriptografi:
    1. Perbandingan apple-to-apple AES-256-CBC, DES-CBC, dan RC4 pada payload identik.
    2. 4 skenario ukuran data nyata SIGAP-PDP.
    3. Metodologi pengukuran & interpretasi hasil untuk skenario bansos.
    """
    user = get_current_user(request, db)
    selected_size_kb = size_kb if size_kb in ALLOWED_BENCHMARK_SIZES_KB else 1024

    comparison = benchmark_ciphers(data_size_kb=selected_size_kb, iterations=5)
    scenarios, last_tested = run_bansos_scenarios_benchmark(iterations=3)

    stats = None
    if user and user.role == "verifikator":
        stats = {
            "pending": db.query(Application).filter(Application.status == "Pending").count()
        }

    return templates.TemplateResponse(
        request=request,
        name="benchmark.html",
        context={
            "current_user": user,
            "stats": stats,
            "selected_size_kb": selected_size_kb,
            "comparison": comparison,
            "scenarios": scenarios,
            "last_tested": last_tested,
        }
    )
