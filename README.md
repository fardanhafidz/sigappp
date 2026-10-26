# Sigapp — Sistem Verifikasi Bansos Terenkripsi

> Tugas Besar Mata Kuliah Keamanan Informasi  
> Aplikasi web monolitik verifikasi bantuan sosial (bansos) dengan perlindungan berkas sensitif menggunakan enkripsi multi-cipher (**AES-256-CBC**, **DES-CBC**, **RC4**) dan key derivation **PBKDF2-HMAC-SHA256**.

---

## 🛠️ Tech Stack

- **Backend**: FastAPI (Python 3.10+) & Uvicorn
- **Templating**: Jinja2 (Server-Side Rendering)
- **Styling**: Tailwind CSS (via CDN, tanpa Node.js / npm)
- **Database**: SQLite (`bansos.db`) via SQLAlchemy ORM
- **Kriptografi**: PyCryptodome (`pycryptodomex`)
  - **AES-256-CBC**: KTP/KK & Slip Gaji (Standar UU PDP)
  - **DES-CBC**: Berita Acara Survei (Interoperabilitas Arsip Legacy)
  - **RC4 Stream**: Video Kondisi Rumah (Payload Media Cepat / High Throughput)
  - **PBKDF2-HMAC-SHA256**: Key Derivation (100.000 iterasi + salt acak)
- **Autentikasi**: Bcrypt (Password Hashing) & PyJWT (HTTP-only Session Cookie)
- **Storage**: Local filesystem ciphertext biner (`storage/encrypted/{file_id}.enc`)

---

## 🚀 Panduan Menjalankan

### A. Windows (PowerShell / CMD)
```bash
# 1. Buat & aktifkan virtual environment
python -m venv venv
.\venv\Scripts\activate

# 2. Pasang dependensi
pip install -r requirements.txt

# 3. Jalankan server
uvicorn app.main:app --reload
```

### B. macOS / Linux (Terminal)
```bash
# 1. Buat & aktifkan virtual environment
python3 -m venv venv
source venv/bin/activate

# 2. Pasang dependensi
pip install -r requirements.txt

# 3. Jalankan server
uvicorn app.main:app --reload
```

Aplikasi aktif di: **`http://127.0.0.1:8000`**

---

## 🔑 Akun Pengujian (Demo)

| Peran | NIK / Username | Password | Deskripsi |
| :--- | :--- | :--- | :--- |
| **Verifikator** | `198001012020011001` | `verifikator123` | Petugas dinas sosial (review berkas, dekripsi on-the-fly, persetujuan/penolakan). |
| **Warga (KPM)** | *Daftar Mandiri* | *Bebas* | Daftar langsung via menu **Daftar Akun** (`/auth/register`) untuk mengajukan bansos. |

> **Audit Performa Kriptografi**: Dapat diakses langsung melalui menu navigasi pada rute **`/benchmark`**.
