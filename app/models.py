from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    nik = Column(String(16), unique=True, index=True, nullable=False)
    nama = Column(String(100), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    kdf_salt = Column(String(64), nullable=False)  # Hex salt acak untuk PBKDF2
    role = Column(String(20), default="kpm", nullable=False)  # "kpm" atau "verifikator"
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relasi
    applications = relationship("Application", back_populates="user", cascade="all, delete-orphan")
    documents = relationship("Document", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User nik={self.nik} role={self.role}>"


class Application(Base):
    __tablename__ = "applications"

    id = Column(Integer, primary_key=True, index=True)
    nomor_pengajuan = Column(String(50), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    keterangan = Column(Text, nullable=True)
    status = Column(String(20), default="Pending", nullable=False)  # Pending, Approved, Rejected
    verifikator_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relasi
    user = relationship("User", back_populates="applications")
    documents = relationship("Document", back_populates="application", cascade="all, delete-orphan", order_by="Document.id")

    def __repr__(self):
        return f"<Application {self.nomor_pengajuan} status={self.status}>"


class Document(Base):
    __tablename__ = "documents"

    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(String(64), unique=True, index=True, nullable=False)  # UUID penyimpanan
    application_id = Column(Integer, ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    category = Column(String(50), nullable=False)  # ktp_kk, slip_gaji, berita_acara, video_rumah
    category_label = Column(String(100), nullable=False)
    original_filename = Column(String(255), nullable=False)
    mime_type = Column(String(100), nullable=False)
    cipher_used = Column(String(50), nullable=False)  # AES-256-CBC, DES-CBC, RC4
    iv_hex = Column(String(64), nullable=True)  # IV hex jika cipher CBC
    file_size = Column(Integer, nullable=False)  # Ukuran dalam bytes
    file_path = Column(String(255), nullable=False)  # Path file .enc pada disk
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relasi
    application = relationship("Application", back_populates="documents")
    user = relationship("User", back_populates="documents")

    def __repr__(self):
        return f"<Document {self.original_filename} ({self.cipher_used})>"
