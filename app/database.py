import os
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker

# Database SQLite lokal: bansos.db di root proyek
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "bansos.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

# Aktifkan Foreign Key constraint pada SQLite
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    from app import models
    from app.auth import get_password_hash
    import secrets

    Base.metadata.create_all(bind=engine)

    # Seed akun verifikator awal jika belum ada
    db = SessionLocal()
    try:
        verifier = db.query(models.User).filter(models.User.role == "verifikator").first()
        if not verifier:
            default_salt = secrets.token_hex(16)
            default_verifier = models.User(
                nik="198001012020011001",
                nama="Petugas Dinsos RI",
                hashed_password=get_password_hash("verifikator123"),
                kdf_salt=default_salt,
                role="verifikator"
            )
            db.add(default_verifier)
            db.commit()
    finally:
        db.close()
