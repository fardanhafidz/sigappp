# Sigapp — Sistem Verifikasi Bansos Terenkripsi

> **Tugas Besar Mata Kuliah Keamanan Informasi**  
> Aplikasi web monolitik verifikasi bantuan sosial (Bansos) dengan proteksi data pribadi multi-cipher berbasis **AES-256-CBC**, **DES-CBC**, **RC4**, dan **PBKDF2-HMAC-SHA256**.

---

## 1. Ringkasan Arsitektur & Tech Stack

Aplikasi dirancang dengan arsitektur **monolitik ringkas, minim konfigurasi, tanpa build tools**, sehingga sangat mudah dijalankan oleh dosen maupun rekan tim saat *clone* repositori:

- **Backend**: FastAPI (Python 3.10+)
- **Template Engine**: Jinja2 (Server-Side Rendering)
- **Styling UI**: Tailwind CSS via CDN (tanpa Node.js, npm, maupun bundler)
- **Database**: SQLite via SQLAlchemy ORM (`bansos.db` tersimpan otomatis secara lokal)
- **Penyimpanan Berkas**: Local storage file biner mentah (`storage/encrypted/{file_id}.enc`)
- **Autentikasi**: Signed HTTP-only Cookie berbasis JWT dengan hashing password menggunakan `passlib[bcrypt]`

---

## 2. Integrasi Kriptografi (Core Requirement)

Sesuai aturan keamanan ketat:
- **Mode ECB DILARANG KERAS**.
- Seluruh berkas diproses secara **lossless** (kembali 100% utuh saat didekripsi on-the-fly).

| Kategori Berkas | Algoritma Cipher | Mode & Parameter | Dasar Pemilihan / Skenario Keamanan |
| :--- | :--- | :--- | :--- |
| **Pindaian KTP / Kartu Keluarga** | **AES-256-CBC** | Kunci 256-bit, IV 16-byte acak, PKCS#7 Padding | Standar Kepatuhan UU Perlindungan Data Pribadi (UU PDP) untuk Data Pribadi Spesifik |
| **Slip Gaji / SKTM** | **AES-256-CBC** | Kunci 256-bit, IV 16-byte acak, PKCS#7 Padding | Perlindungan kerahasiaan Data Finansial KPM dari kebocoran berkas |
| **Berita Acara Survei** | **DES-CBC** | Kunci 64-bit (56-bit efektif), IV 8-byte acak, PKCS#7 Padding | Interoperabilitas dengan sistem arsip legacy pemerintah daerah |
| **Video Kondisi Rumah** | **RC4** | Stream Cipher murni (Kunci 128-bit, Keystream XOR, Tanpa IV) | Throughput tinggi dan pemrosesan stream cepat untuk berkas media berukuran besar |

### Key Derivation Function (KDF)
Kunci enkripsi diturunkan dari kredensial pengguna menggunakan **PBKDF2-HMAC-SHA256** dengan **100.000 iterasi** serta **Salt acak 16-byte** yang digenerate saat registrasi dan disimpan pada tabel database `users.kdf_salt`.

### Alur Simpan & Unduh Berkas
1. Warga (KPM) mengunggah berkas via formulir HTML (`multipart/form-data`).
2. Server membaca *bytes* asli berkas.
3. Fungsi enkripsi pada `app/crypto_engine.py` dipanggil menghasilkan ciphertext biner dan IV acak.
4. Ciphertext disimpan ke disk: `storage/encrypted/{file_id}.enc`.
5. Metadata (`original_filename`, `mime_type`, `cipher_used`, `iv_hex`, `file_size`, `user_id`, `application_id`) dicatat di SQLite.
6. Saat diunduh kembali oleh KPM atau Verifikator, server membaca file `.enc` dari disk, mendekripsi on-the-fly dengan kunci & IV yang sesuai, lalu mengirimkan payload asli secara streaming (`StreamingResponse`) dengan MIME type dan header `Content-Disposition` aslinya.

---

## 3. Struktur Direktori

```text
bansostrust/
├── app/
│   ├── __init__.py
│   ├── main.py              # Inisialisasi FastAPI, lifespan, & router registration
│   ├── database.py          # Koneksi SQLite (bansos.db) & session SQLAlchemy
│   ├── models.py            # Model User, Application, dan Document
│   ├── auth.py              # Password hashing bcrypt, JWT cookie, & role checker
│   ├── crypto_engine.py     # Modul kripto (AES-256-CBC, DES-CBC, RC4, PBKDF2)
│   ├── routes/
│   │   ├── auth_routes.py   # Register KPM, Login, Logout
│   │   ├── kpm_routes.py    # Form pengajuan bansos, list permohonan, download
│   │   ├── verifier_routes.py # Review permohonan warga, verifikasi, update status
│   │   └── benchmark_routes.py # Halaman pengujian & visualisasi performa cipher
│   └── templates/           # File HTML Jinja2 (Tailwind CSS via CDN)
│       ├── base.html        # Layout utama + Navbar + Tailwind CDN
│       ├── login.html       # Halaman login portal
│       ├── register.html    # Halaman pendaftaran akun warga KPM
│       ├── kpm_dashboard.html # Dashboard warga & daftar berkas miliknya
│       ├── apply_form.html  # Formulir pengajuan bansos & upload 4 berkas
│       ├── verifier_dashboard.html # Dashboard petugas verifikator (stats & filter)
│       ├── verifier_detail.html    # Halaman detail review & verifikasi faktual
│       └── benchmark.html   # Halaman visual benchmark ketiga cipher
├── storage/
│   └── encrypted/           # Folder penyimpanan file biner mentah (.enc)
├── requirements.txt
└── README.md
```

---

## 4. Panduan Menjalankan Aplikasi

### Langkah 1: Buat & Aktifkan Virtual Environment (venv)
```bash
# 1. Buat virtual environment (cukup sekali)
python -m venv venv

# 2. Aktifkan venv:
# Pada Windows PowerShell:
.\venv\Scripts\Activate.ps1

# Atau pada Windows CMD:
venv\Scripts\activate
```
> *Catatan PowerShell*: Jika muncul pesan Execution Policy, jalankan `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` lalu ulangi `.\venv\Scripts\Activate.ps1`.

### Langkah 2: Pasang Dependensi
```bash
pip install -r requirements.txt
```

### Langkah 3: Jalankan Server FastAPI
```bash
# Jika venv sudah aktif:
uvicorn app.main:app --reload

# Atau jalankan langsung tanpa aktivasi terminal:
.\venv\Scripts\python.exe -m uvicorn app.main:app --reload
```
Aplikasi akan aktif di alamat: **`http://127.0.0.1:8000`**

*(Database SQLite `bansos.db` dan folder `storage/encrypted/` akan diinisialisasi secara otomatis saat server pertama kali dijalankan).*

---

## 5. Kredensial Pengujian (Demo Testing)

### A. Akun Petugas Verifikator Dinsos (Telah Di-seed Otomatis)
- **NIK**: `198001012020011001`
- **Password**: `verifikator123`
- **Peran**: Verifikator (melihat seluruh pengajuan, mengunduh/mendekripsi bukti berkas, menyetujui/menolak status permohonan).

### B. Akun Warga / KPM
- Pengguna dapat langsung mendaftar secara mandiri melalui menu **Daftar KPM** (`/auth/register`) dengan menginputkan NIK 16-digit, Nama, dan Password.

### C. Halaman Benchmark Kriptografi
- Dapat diakses kapan saja pada menu navigasi atas di URL **`/benchmark`** untuk menguji kecepatan enkripsi & dekripsi (ms & MB/s) pada berbagai ukuran berkas (64 KB hingga 5 MB).
