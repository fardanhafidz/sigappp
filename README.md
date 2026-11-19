# SIGAP-PDP — Sistem Integrasi Bansos Tanggap Perlindungan Data Pribadi

> Tugas Besar Mata Kuliah Keamanan Informasi  
> Aplikasi web monolitik pengajuan & verifikasi bantuan sosial (bansos) dengan perlindungan data pribadi dan berkas sensitif menggunakan **AES-256-CBC**, **DES-CBC**, **RC4 + Nonce**, derivasi kunci **PBKDF2-HMAC-SHA256**, dan verifikasi integritas **SHA-256**.

---

## 🛠️ Tech Stack & Keamanan

- **Backend**: FastAPI (Python 3.10+) & Uvicorn
- **Templating**: Jinja2 (Server-Side Rendering) + Tailwind CSS (CDN)
- **Database**: SQLite (`bansos.db`) via SQLAlchemy ORM
- **Kriptografi**: PyCryptodome (`pycryptodomex`)
  - **AES-256-CBC**: Data Pribadi Alamat/Keterangan (SQLite), Pindaian KTP/KK & SKTM/Slip Gaji (Kepatuhan **UU No. 27 Tahun 2022 / UU PDP**)
  - **DES-CBC**: Berita Acara Survei Lapangan (Simulasi Interoperabilitas Arsip *Legacy* Pemda)
  - **RC4 + Nonce 16-Byte**: Video Kondisi Rumah (High Throughput Stream Cipher + pencegahan *keystream reuse*)
  - **PBKDF2-HMAC-SHA256**: Key Derivation (`100.000` iterasi dari `APP_MASTER_KEY` di luar DB + NIK + `salt` acak per akun)
  - **SHA-256 Checksum**: Verifikasi keutuhan berkas (*lossless*) setiap kali dekripsi dilakukan
- **Autentikasi**: Bcrypt (Password Hashing) & PyJWT (HTTP-only Session Cookie)
- **Storage**: Ciphertext biner di sistem berkas lokal (`storage/encrypted/{file_id}.enc`)

---

## 🚀 Panduan Menjalankan

### A. Windows (PowerShell / CMD)
```powershell
# 1. Aktifkan virtual environment
.\venv\Scripts\activate

# 2. (Opsional) Reset & isi data demo realistis + berkas demo_files/
python seed_demo.py

# 3. Jalankan server
uvicorn app.main:app --reload
```

### B. macOS / Linux (Terminal)
```bash
source venv/bin/activate
python seed_demo.py
uvicorn app.main:app --reload
```

Aplikasi aktif di: **`http://127.0.0.1:8000`**

---

## 🔑 Akun Demo & Reset Data

Gunakan **`python seed_demo.py`** kapan saja sebelum presentasi untuk mereset `bansos.db`, berkas terenkripsi `storage/encrypted/*.enc`, dan folder `demo_files/`.

| Peran | NIK | Password | Status / Kegunaan Demo |
| :--- | :--- | :--- | :--- |
| **Verifikator (Dinsos)** | `198001012020011001` | `verifikator123` | Tinjau antrean, unduh & dekripsi berkas warga, Setujui/Tolak pengajuan. |
| **Warga (KPM 1)** | `3578011508850001` | `warga123` | **Siti Aminah** — Status `Pending` (siap direview Verifikator). |
| **Warga (KPM 2)** | `3578022405790002` | `warga123` | **Slamet Raharjo** — Status `Approved` (tampil di Keluarga Penerima). |
| **Warga (KPM 3)** | `3578031103910003` | `warga123` | **Hendra Wijaya** — Status `Rejected` (contoh catatan penolakan). |
| **Warga (KPM 4)** | `3578040912880004` | `warga123` | **Rina Kusumawati** — Belum punya pengajuan; siap live-upload memakai `demo_files/`. |

> **Audit Performa & Evaluasi Kriptografi**: Dapat diakses langsung melalui menu **`/benchmark`** (perbandingan *apple-to-apple* `100 KB` / `1 MB` / `5 MB`, 4 skenario nyata, serta metodologi & interpretasi hasil).
