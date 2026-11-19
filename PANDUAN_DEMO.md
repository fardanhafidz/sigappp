# Panduan Demo, Pembagian Tim & Simulasi Q&A — SIGAP-PDP

> **Judul Proyek**: **SIGAP-PDP** (*Sistem Integrasi Bansos Tanggap Perlindungan Data Pribadi*)  
> **Tim (4 Orang)**: Maulana Rhys Pradana • Muhammad Fardan Hafidz • Muhammad Fasya Atthaya Rosyada • Sandi Suryo Nugroho  
> **Target Durasi Presentasi + Demo**: ~12–15 menit (+ Q&A dosen)

---

## 1. Checklist Persiapan 10 Menit Sebelum Demo

Jalankan langkah berikut di PowerShell pada folder proyek (`c:\Kuliah\Mata Kuliah\Keamanan Informasi`):

```powershell
# 1. Pastikan server uvicorn lama sudah berhenti (Ctrl+C jika masih jalan)
# 2. Reset & isi ulang database demo yang bersih + folder demo_files/
.\venv\Scripts\python.exe seed_demo.py

# 3. Jalankan server web
.\venv\Scripts\uvicorn.exe app.main:app --reload
```

Aplikasi berjalan di: **`http://127.0.0.1:8000`**

> **Catatan Penting Sebelum Maju**:
> - Jika sebelumnya sempat latihan klik Setujui/Tolak atau upload berkas, **matikan server dulu (`Ctrl+C`) lalu jalankan ulang `.\venv\Scripts\python.exe seed_demo.py`** sebelum presentasi dimulai agar data kembali bersih seperti awal.
> - **Logout** (atau gunakan mode Incognito untuk peran kedua) supaya cookie sesi lama tidak tertukar.

### Jendela & Tab yang Perlu Disiapkan Sebelum Giliran
1. **Browser Utama**: Buka `http://127.0.0.1:8000/auth/login` (untuk demo KPM & Verifikator).
2. **Tab Incognito / Browser Kedua (Opsional)**: Siapkan untuk uji RBAC/IDOR atau login Verifikator paralel tanpa perlu bolak-balik logout.
3. **File Explorer**: Buka 2 jendela/tab siap pakai:
   - Folder `demo_files/` (berisi 4 berkas valid siap unggah untuk akun Rina Kusumawati).
   - Folder `storage/encrypted/` (untuk membuka salah satu file `.enc` di Notepad sebagai bukti ciphertext acak).
4. **VS Code**: Buka [app/crypto_engine.py](app/crypto_engine.py) agar tinggal *alt-tab* saat menjelaskan implementasi kriptografi.
5. **Terminal PowerShell kedua**: Siap di folder proyek untuk menjalankan *one-liner* inspeksi `bansos.db` (lihat bagian Cheat Sheet di bawah).

---

## 2. Daftar Akun Demo & Berkas Uji

### A. Akun Siap Pakai (Hasil `seed_demo.py`)

| Peran | NIK / NIP | Password | Status Saat Mulai | Kegunaan Saat Demo |
| :--- | :--- | :--- | :--- | :--- |
| **Verifikator (Dinsos)** | `198001012020011001` | `verifikator123` | Aktif | Review antrean, dekripsi *on-the-fly*, Setujui/Tolak berkas warga |
| **Warga 1 — Siti Aminah** | `3578011508850001` | `warga123` | `Pending` | Pengajuan antrean masuk (direview Verifikator saat demo, `doc_id 1–4`) |
| **Warga 2 — Slamet Raharjo** | `3578022405790002` | `warga123` | `Approved` | Mengisi menu `Keluarga Penerima` + target uji **IDOR** (`/kpm/download/5`) |
| **Warga 3 — Hendra Wijaya** | `3578031103910003` | `warga123` | `Rejected` | Contoh status ditolak beserta catatan resmi verifikator |
| **Warga 4 — Rina Kusumawati** | `3578040912880004` | `warga123` | *Belum mengajukan* | **Akun utama live-demo upload 4 berkas** memakai `demo_files/` |

### B. Berkas Siap Unggah di Folder `demo_files/`

| Nama File | Kategori Form | Cipher & Mode | Dasar Proteksi |
| :--- | :--- | :--- | :--- |
| `KTP_KK_Rina_Kusumawati.png` | Pindaian KTP / KK | **AES-256-CBC** (IV 16 B, PKCS#7) | Data Pribadi Spesifik & Umum (UU PDP Ps. 4) |
| `SKTM_Rina_Kusumawati.pdf` | Slip Gaji / SKTM | **AES-256-CBC** (IV 16 B, PKCS#7) | Data Keuangan Pribadi (UU PDP Ps. 4 ayat 2) |
| `Berita_Acara_Survei_Rina.docx` | Berita Acara Survei | **DES-CBC** (IV 8 B, PKCS#7) | Simulasi Interoperabilitas Arsip *Legacy* Pemda |
| `Video_Kondisi_Rumah_Rina.avi` | Video Kondisi Rumah | **RC4 + Nonce 16 B** | *Stream* Video Throughput Tinggi + anti *keystream reuse* |

*(Ditambah **Data Pribadi Teks** berupa Alamat Domisili / Keterangan di tabel `applications` yang juga dienkripsi **AES-256-CBC** sebelum masuk SQLite.)*

---

## 3. Pembagian Peran 4 Orang, Alur Demo & Skrip Bicara

### Bagian 1 — Anggota 1: Pembukaan, Skenario Nyata, Dasar Hukum UU PDP & Arsitektur (~2–3 Menit)

**Yang ditampilkan di layar**: Halaman `/auth/login` + diagram/ringkasan di [README.md](README.md) atau [Laporan Tugas KI.pdf](Laporan%20Tugas%20KI.pdf).

**Poin Teknis yang Wajib Tersampaikan**:
1. Skenario konkret: **SIGAP-PDP** (penyaluran & verifikasi Bantuan Sosial / DTKS Dinas Sosial), **bukan** layanan enkripsi file generik.
2. Pengguna & data: **Warga/KPM** mengunggah data alamat, scan KTP/KK (gambar), SKTM (PDF), Berita Acara Survei (DOCX), dan Video kondisi rumah (AVI); **Verifikator Dinsos** meninjau kelayakan.
3. Mengapa wajib dilindungi (**UU No. 27 Tahun 2022 / UU PDP**): data penerima bansos sangat rawan pencurian identitas, penipuan pinjol ilegal, dan *doxxing* kelompok rentan.
   - **Pasal 4 ayat (2)**: Data Pribadi Spesifik (data keuangan/SKTM, biometrik/foto KTP).
   - **Pasal 4 ayat (3)**: Data Pribadi Umum (nama lengkap, NIK, alamat domisili).
4. Arsitektur: *Lean monolith* Python **FastAPI + SQLite + PyCryptodome** tanpa mode **ECB** sama sekali.

**Skrip Bicara (Anggota 1)**:
> *"Selamat malam Bapak/Ibu Dosen, kami dari kelompok SIGAP-PDP akan mendemokan aplikasi web Sistem Integrasi Bansos Tanggap Perlindungan Data Pribadi. Skenario dunia nyata yang kami pilih adalah proses pengajuan dan verifikasi bantuan sosial berbasis DTKS.*
>
> *Di sistem ini ada dua aktor utama: **Warga (KPM)** yang mengajukan bantuan dan **Verifikator Dinas Sosial** yang memverifikasi berkas. Data yang dikelola mencakup data pribadi tekstual seperti alamat domisili, pindaian KTP/KK dalam bentuk gambar PNG, dokumen perkantoran PDF dan DOCX berupa SKTM serta Berita Acara Survei, hingga video kondisi rumah format AVI.*
>
> *Berdasarkan **UU No. 27 Tahun 2022 tentang Perlindungan Data Pribadi** — khususnya Pasal 4 ayat 2 dan ayat 3 mengenai data pribadi spesifik dan umum — kebocoran berkas KTP atau keterangan ekonomi warga rentan disalahgunakan untuk pinjol ilegal maupun penipuan. Karena itu seluruh data yang disimpan kami proteksi dengan tiga algoritma yang dipetakan sesuai kebutuhan: **AES-256-CBC** untuk data sensitif UU PDP, **DES-CBC** untuk skenario kompatibilitas arsip legacy pemda, dan **RC4 dengan Nonce unik** untuk payload video berukuran besar. Seluruh cipher blok menggunakan mode **CBC dengan IV acak**, tanpa mode ECB. Untuk alur warga dan bukti enkripsinya akan langsung didemokan oleh rekan saya."*

---

### Bagian 2 — Anggota 2: Live Demo Sisi Warga (KPM) + Bukti Enkripsi *At-Rest* (~3–4 Menit)

**Langkah Aksi di Layar**:
1. Di `/auth/login`, masukkan NIK **`3578040912880004`** dan Password **`warga123`** (Rina Kusumawati) → klik **Masuk**.
2. Arahkan ke menu **Buat Pengajuan** (`/kpm/apply`).
3. Isi **Alamat Domisili / Keterangan Permohonan**:
   `Jl. Klampis Harapan No. 8, Kec. Sukolilo, Surabaya - Bantuan Modal Usaha Jajanan`
4. Unggah ke-4 file dari folder `demo_files/`:
   - Pindaian KTP / KK → `KTP_KK_Rina_Kusumawati.png`
   - SKTM → `SKTM_Rina_Kusumawati.pdf`
   - Berita Acara → `Berita_Acara_Survei_Rina.docx`
   - Video Hunian → `Video_Kondisi_Rumah_Rina.avi`
5. Klik **Kirim Pengajuan** → otomatis masuk ke `/kpm/dashboard` dengan banner status `Pending` dan 4 dokumen beserta badge **cipher** dan **SHA-256**.
6. **Bukti Lossless**: Klik **Unduh Berkas Asli** pada salah satu dokumen (misal PNG KTP atau PDF SKTM atau Video AVI) → buka langsung hasilnya untuk menunjukkan file kembali utuh 100%.
7. **Bukti Enkripsi *At-Rest***:
   - Buka folder `storage/encrypted/`, klik kanan file `.enc` terbaru → **Open with Notepad** (tunjukkan isinya biner acak, tidak terbaca sama sekali).
   - Di terminal PowerShell kedua, jalankan **one-liner inspeksi SQLite** (lihat Cheat Sheet) untuk memperlihatkan kolom `applications.keterangan` tersimpan sebagai `ENC:AES256CBC:<iv>:<ciphertext>`, lengkap dengan `iv_hex` dan `sha256_hash`.

**Skrip Bicara (Anggota 2)**:
> *"Sekarang saya login sebagai Warga atas nama **Ibu Rina Kusumawati** yang belum memiliki pengajuan. Di halaman Formulir Pengajuan Baru, kami mengisi alamat domisili dan mengunggah empat kategori berkas yang disyaratkan tugas: pindaian KTP dalam format PNG, SKTM dalam PDF, Berita Acara dalam DOCX, dan rekaman kondisi rumah berformat AVI.*
>
> *Begitu tombol Kirim Pengajuan ditekan, server langsung menurunkan kunci unik pengguna via PBKDF2-HMAC-SHA256, menghitung sidik jari **SHA-256** setiap berkas, lalu mengenkripsi alamat domisili serta keempat berkas tersebut.*
>
> *Bisa dilihat di Beranda Warga, status pengajuan kini Pending, dan setiap berkas menampilkan cipher yang digunakan serta potongan hash SHA-256. Jika saya klik **Unduh Berkas Asli**, file didekripsi di memori server dan dapat langsung dibuka dengan utuh tanpa cacat atau lossless.*
>
> *Sebagai pembuktian bahwa data yang tersimpan di server benar-benar terenkripsi: jika kita lihat di folder `storage/encrypted/` menggunakan Notepad, seluruh isi file `.enc` berupa byte acak yang tidak terbaca. Begitu pula di database SQLite `bansos.db`, kolom alamat `keterangan` tersimpan dalam format `ENC:AES256CBC:` sehingga meskipun file database dibuka langsung, alamat asli warga tetap terlindungi."*

---

### Bagian 3 — Anggota 3: Uji Keamanan IDOR/RBAC, Live Demo Verifikator & Bedah `crypto_engine.py` (~3–4 Menit)

**Langkah Aksi di Layar**:
1. **Uji Kontrol Akses & Anti-IDOR** *(masih login sebagai Rina / akun KPM)*:
   - Ketik URL `http://127.0.0.1:8000/kpm/download/5` (ini `doc_id=5`, berkas KTP milik **Slamet Raharjo**, warga lain) → tunjukkan server menolak dengan **`404 Dokumen tidak ditemukan atau akses ditolak`**.
   - Ketik URL `http://127.0.0.1:8000/verifier/dashboard` → tunjukkan redirect ditolak **`Akses khusus petugas verifikator`**.
2. **Logout**, lalu login sebagai **Verifikator**: NIP **`198001012020011001`**, Password **`verifikator123`**.
3. Di `/verifier/dashboard`, tunjukkan metrik antrean & tabel pengajuan (alamat seluruh warga otomatis didekripsi untuk petugas yang berhak).
4. Klik **Review Berkas** pada **Siti Aminah** (`/verifier/application/1`):
   - Tunjukkan badge `AES-256-CBC`, `DES-CBC`, `RC4`, nilai `IV:` / `Nonce:`, serta `SHA-256:`.
   - Klik **Lihat** pada `SKTM_Siti_Aminah.pdf` atau `Berita_Acara_Siti_Aminah.docx` → buka untuk membuktikan Verifikator bisa memverifikasi berkas secara *on-the-fly* tanpa pernah menulis file plaintext sementara di disk.
   - Isi catatan verifikator singkat (misal: *"Berkas lengkap dan kondisi rumah tervalidasi layak menerima PKH."*), lalu klik **Setujui**.
5. Buka sekilas menu **Keluarga Penerima** (`/verifier/keluarga` — Siti Aminah kini masuk daftar disetujui), **Arsip Berkas** (`/verifier/arsip` — filter AES/DES/RC4), dan **Buku Alamat RT/RW** (`/verifier/alamat`).
6. Pindah ke **VS Code** ([app/crypto_engine.py](app/crypto_engine.py)), gulir cepat 5 blok utama:
   - `APP_MASTER_KEY` + `get_user_cipher_key()` (`PBKDF2-HMAC-SHA256`, 100.000 iterasi).
   - `encrypt_aes_256_cbc` / `decrypt_aes_256_cbc` (IV acak 16B, PKCS#7, mode CBC).
   - `encrypt_des_cbc` / `decrypt_des_cbc` (IV acak 8B, PKCS#7, mode CBC).
   - `encrypt_rc4` / `decrypt_rc4` (Nonce acak 16B digabung via SHA-256 mencegah *keystream reuse*).
   - `compute_sha256` & `verify_sha256` (`hmac.compare_digest`).

**Skrip Bicara (Anggota 3)**:
> *"Selanjutnya saya akan mendemokan isolasi hak akses dan alur Verifikator. Saat ini kita masih login sebagai warga. Jika warga mencoba mengakses berkas milik warga lain lewat URL `/kpm/download/5`, server langsung memblokir dengan status 404 karena query selalu mengunci kepemilikan `user_id`. Demikian juga jika warga mencoba membuka `/verifier/dashboard`, sistem otomatis menolak.*
>
> *Sekarang saya keluar dan masuk sebagai **Petugas Verifikator Dinas Sosial** menggunakan NIP 18 digit. Di Dashboard Verifikator, petugas dapat melihat antrean warga beserta alamat yang otomatis didekripsi. Pada detail pengajuan **Ibu Siti Aminah**, petugas dapat melihat keempat berkas beserta metadata cipher, potongan IV atau Nonce, dan hash SHA-256-nya. Saat petugas mengklik **Lihat**, server mendekripsi berkas secara on-the-fly di RAM lewat `StreamingResponse` tanpa menyimpan file sementara di disk, lalu memverifikasi kecocokan hash SHA-256 sebelum mengirimkannya.*
>
> *Setelah berkas sesuai, petugas mengisi catatan dan mengklik **Setujui**, sehingga data Ibu Siti Aminah otomatis berpindah ke daftar Keluarga Penerima.*
>
> *Secara teknis di dalam [app/crypto_engine.py](app/crypto_engine.py), seluruh kunci diturunkan menggunakan **PBKDF2-HMAC-SHA256** sebanyak **100.000 iterasi** dari **Master Key yang dipisah di luar database**, digabung NIK dan salt unik per pengguna. Mode blok AES-256 dan DES wajib memakai **CBC + PKCS#7 + IV acak**, sedangkan stream cipher RC4 kami perkuat dengan **nonce acak 16-byte per berkas** agar keystream tidak pernah berulang."*

---

### Bagian 4 — Anggota 4: Live Demo Benchmark (`/benchmark`), Interpretasi & Penutup (~3 Menit)

**Langkah Aksi di Layar**:
1. Klik menu **Audit Kriptografi** (`/benchmark`).
2. Tunjukkan baris **Lingkungan Aktual** (`Python 3.12.2 • PyCryptodome 3.24.1 • Windows 11`).
3. Tunjukkan **Tabel 1: Perbandingan Sejajar (*Apple-to-Apple*)** pada ukuran **`1 MB`**:
   - Sorot waktu enkripsi/dekripsi (ms), throughput (MB/s), overhead padding (`+16 B` AES, `+8 B` DES, `+0 B` RC4), dan status `Lossless SHA-256 ✓`.
4. Klik tombol pengubah payload **`5 MB`** (`/benchmark?size_kb=5120`) lalu klik **Jalankan Ulang Benchmark** agar dosen melihat pengukuran berjalan live.
5. Tunjukkan **Tabel 2 (4 Skenario Nyata SIGAP-PDP)** dan **Bagian 3 (Metodologi & Interpretasi Hasil)** langsung di layar.

**Skrip Bicara (Anggota 4)**:
> *"Untuk memenuhi evaluasi perbandingan ketiga cipher secara objektif, kami menyediakan halaman Audit Kriptografi pada rute `/benchmark`.*
>
> *Pertama, apa yang kami ukur dan bagaimana kami menjamin keandalannya: kami mengukur waktu enkripsi dan dekripsi dalam milidetik, throughput dalam MB per detik, overhead ukuran padding, serta verifikasi keutuhan SHA-256. Agar adil dan apple-to-apple, ketiga algoritma diuji pada **payload acak yang identik** — bisa diganti antara 100 KB, 1 MB, dan 5 MB — menggunakan timer resolusi tinggi `time.perf_counter()`, dengan **1 kali warm-up** sebelum mengambil **rata-rata 5 iterasi**.*
>
> *Apa arti hasilnya bagi skenario SIGAP-PDP?*
> *1. **AES-256-CBC** memberikan kombinasi keamanan tertinggi dengan kecepatan sangat tinggi — bahkan pada payload 1 MB di CPU modern yang mendukung instruksi hardware **AES-NI**, AES-256-CBC bisa menyaingi atau melampaui RC4. Ini menegaskan bahwa AES-256-CBC adalah pilihan paling tepat untuk data pribadi sensitif KTP, SKTM, dan alamat sesuai UU PDP.*
> *2. **DES-CBC** konsisten menjadi yang paling lambat (sekitar 4–5 kali lebih lambat dari AES/RC4) karena ukuran blok kecil 8 byte dan 16 ronde Feistel, selain kunci efektifnya hanya 56-bit yang rentan brute-force. Oleh karena itu di arsitektur kami penggunaannya dibatasi hanya untuk simulasi interoperabilitas arsip legacy pemda.*
> *3. **RC4 + Nonce** tidak membutuhkan padding sehingga overhead-nya 0 byte dan tetap memberikan throughput ratusan MB/s untuk video berukuran besar. Namun karena RC4 memiliki kelemahan historis pada bias keystream (RFC 7465), sistem kami mewajibkan nonce acak unik per berkas plus cek integritas SHA-256, dan untuk implementasi produksi ke depan kami rekomendasikan migrasi ke AES-GCM atau ChaCha20-Poly1305.*
>
> *Sekian demo dan pemaparan dari kelompok kami. Kami persilakan Bapak/Ibu Dosen apabila ada pertanyaan atau masukan."*

---

## 4. Bank Soal & Jawaban Cerdas Q&A Dosen (12 Pertanyaan Umum & "Jebakan")

### Q1. Kenapa mode ECB dilarang keras di tugas ini, dan bagaimana CBC mengatasinya?
- **Jawaban**: Pada **ECB (*Electronic Codebook*)**, blok plaintext yang identik dengan kunci yang sama selalu menghasilkan blok ciphertext yang identik, sehingga pola visual gambar (seperti ilustrasi *ECB Penguin* atau struktur pindaian KTP) tetap terlihat. Pada **CBC (*Cipher Block Chaining*)**, setiap blok plaintext di-XOR dulu dengan blok ciphertext sebelumnya (dan blok pertama di-XOR dengan **IV acak** 16 byte untuk AES / 8 byte untuk DES). Karena IV dibuat acak per file via `os.urandom()`, dua file yang sama persis akan menghasilkan ciphertext yang berbeda total.

### Q2. Katanya melindungi data pribadi, kenapa `nik` dan `nama` di tabel `users` masih plaintext, sementara `keterangan` (alamat) dienkripsi?
- **Jawaban**: Itu *design trade-off* yang disengaja: kolom `nik` digunakan sebagai *login lookup key* dan indeks unik SQL (`WHERE users.nik = ...`). Jika `nik` dienkripsi memakai IV acak, query SQL tidak bisa mencocokkannya secara langsung. Sementara `applications.keterangan` (alamat domisili lengkap & keterangan bantuan) tidak dipakai untuk login sehingga aman dienkripsi penuh dengan `AES-256-CBC`. Di sistem produksi skala penuh, pencarian `nik` bisa tetap dienkripsi sambil memakai *HMAC blind index* terpisah.

### Q3. Bagaimana Verifikator bisa mendekripsi berkas warga tanpa mengetahui password warga tersebut?
- **Jawaban**: Kunci enkripsi berkas tidak diturunkan dari password login warga, melainkan dari **`APP_MASTER_KEY`** (rahasia server yang disimpan di environment variable di luar database) digabung dengan `user.nik` dan `user.kdf_salt` via `PBKDF2-HMAC-SHA256`. Dengan cara ini: (1) Verifikator yang terautentikasi tetap bisa memverifikasi berkas warga, (2) jika warga mengganti password login, berkas lamanya tidak rusak, dan (3) kunci tiap warga tetap terisolasi berbeda satu sama lain.

### Q4. Bagaimana jika attacker berhasil mencuri file `bansos.db` sekaligus seluruh folder `storage/encrypted/`?
- **Jawaban**: Attacker **tetap tidak bisa mendekripsi berkas maupun alamat domisili**, karena `APP_MASTER_KEY` tidak disimpan di dalam `bansos.db` maupun folder `storage/`. Selain itu, password akun di `users.hashed_password` sudah di-hash adaptif menggunakan **bcrypt** (dengan salt acak per akun), sehingga tidak bisa dibalik menjadi plaintext. Di produksi, `APP_MASTER_KEY` ditempatkan pada KMS/HSM (*Key Management Service*).

### Q5. DES dan RC4 kan sudah usang/tidak aman menurut standar modern, kenapa masih dipakai?
- **Jawaban**: Secara akademis proyek ini memang mewajibkan implementasi dan evaluasi komparatif **AES, DES, dan RC4** dalam satu skenario konkret. Alih-alih menerapkannya secara acak, kami memberi peran yang realistis dan mengisolasi risikonya:
  - **AES-256-CBC** melindungi seluruh data paling sensitif (KTP/KK, SKTM, Alamat).
  - **DES-CBC** ditempatkan pada simulasi interoperabilitas sistem arsip *legacy* pemda (dengan catatan eksplisit di UI dan benchmark bahwa DES tidak layak untuk data rahasia baru karena kunci efektif 56-bit dan risiko *Sweet32* blok 64-bit).
  - **RC4** ditempatkan pada file video berukuran besar, dilengkapi **nonce acak 16-byte per file** untuk mencegah *keystream reuse* serta catatan rekomendasi migrasi produksi ke **AES-GCM / ChaCha20-Poly1305**.

### Q6. Di halaman `/benchmark` untuk ukuran 1 MB, kok AES-256-CBC bisa lebih cepat daripada RC4? Bukannya stream cipher harusnya lebih cepat?
- **Jawaban**: Itu temuan empiris yang sangat bagus dari pengukuran nyata! Secara teoretis di software murni, RC4 memang sangat ringan. Namun prosesor modern (`x86_64` / `AMD64`) memiliki instruksi hardware khusus **AES-NI** (*AES New Instructions*) yang dimanfaatkan oleh PyCryptodome di level C/assembly, sementara RC4 dijalankan sebagai loop software biasa dan kini jarang dioptimasi di hardware. Ketika ukuran payload lebih besar atau melewati cache CPU (misal uji `5 MB`), perbandingan throughput bisa berubah tergantung bandwidth memori — itulah kenapa mengukur langsung di mesin target jauh lebih jujur daripada mengutip teori mentah-mentah.

### Q7. Apa risiko terbesar RC4 kalau dipakai langsung dengan satu kunci per user, dan bagaimana kode kalian mencegahnya?
- **Jawaban**: Jika satu kunci RC4 dipakai mengenkripsi lebih dari satu file (atau file yang sama diunggah ulang setelah direvisi), kedua ciphertext memakai *keystream* yang persis sama sehingga attacker yang menyadap kedua ciphertext bisa melakukan $C_1 \oplus C_2 = P_1 \oplus P_2$ (*keystream reuse / many-time pad*). Di `crypto_engine.py`, fungsi `encrypt_rc4()` selalu membuat **nonce acak 16-byte** (`os.urandom(16)`) per berkas dan menurunkan kunci efektif per file lewat `SHA-256(base_key + nonce)[:16]`. Jadi setiap enkripsi menghasilkan keystream yang benar-benar baru.

### Q8. Mode CBC dan RC4 kan hanya menjamin *Confidentiality*, belum *Authenticity/Integrity* (rentan *bit-flipping* / *padding oracle*). Bagaimana kalian memastikan file kembali utuh?
- **Jawaban**: Sebelum berkas dienkripsi, kami menghitung hash **SHA-256** plaintext asli dan menyimpannya di kolom `documents.sha256_hash`. Saat didekripsi pada endpoint unduh, sistem menghitung ulang SHA-256 hasil dekripsi dan mencocokkannya dengan `hmac.compare_digest()`. Jika ada 1 byte saja pada ciphertext di disk yang korup atau dimodifikasi (termasuk pada RC4 yang tidak memiliki error padding), verifikasi SHA-256 langsung gagal dan server menolak mengembalikan file. Sebagai penyempurnaan produksi, skema ini dapat ditingkatkan ke *AEAD* (**AES-256-GCM**) atau **Encrypt-then-MAC (HMAC-SHA256 atas IV + ciphertext)**.

### Q9. Saat Verifikator atau KPM mengunduh berkas, apakah file plaintext sempat ditulis ke hard disk server?
- **Jawaban**: **Tidak pernah.** File `.enc` dibaca ke memori server, didekripsi langsung dalam variabel `bytes` di RAM, dicek SHA-256-nya, lalu dikirim ke browser lewat `io.BytesIO` dan `StreamingResponse` FastAPI. Jadi tidak ada residu file sementara yang tertinggal di disk server.

### Q10. Pasal apa saja di UU PDP (UU No. 27 Tahun 2022) yang menjadi dasar perancangan aplikasi ini?
- **Jawaban**:
  - **Pasal 4 ayat (2)**: Data Pribadi Spesifik — di proyek ini mencakup data keuangan pribadi (SKTM/slip gaji) dan data identitas/biometrik foto pada pindaian KTP/KK.
  - **Pasal 4 ayat (3)**: Data Pribadi Umum — nama lengkap, NIK, dan alamat domisili.
  - **Pasal 20 & Pasal 35**: Kewajiban Pengendali Data Pribadi (dalam skenario ini Dinas Sosial) untuk memiliki dasar pemrosesan yang sah dan melindungi keamanan data pribadi dari pemrosesan tidak sah serta kebocoran (*encryption at-rest* + kontrol akses RBAC).

### Q11. Kenapa Verifikator bisa membuka file warga? Bukannya di soal diminta "hanya pengguna yang terautentikasi yang boleh mengambil kembali datanya sendiri"?
- **Jawaban**: Ada dua lapisan di sini:
  1. Pada sisi warga (`/kpm/download/{doc_id}`), query SQL memfilter ketat `Document.user_id == user.id`. Jadi warga A **mustahil** mengambil berkas warga B (langsung diblokir `404`).
  2. Dalam skenario dunia nyata penyaluran bansos, tujuan warga mengunggah syarat adalah agar diverifikasi oleh petugas resmi. Oleh karena itu akses lintas-pemohon hanya diberikan kepada peran `verifikator` yang terautentikasi melalui mekanisme RBAC (`RoleChecker` + JWT HTTP-only cookie).

### Q12. Bagaimana kalian memastikan angka di halaman `/benchmark` andal dan bukan sekadar angka acak sekali jalan?
- **Jawaban**: Di `benchmark_ciphers()`, kami memakai: (1) satu buffer acak identik (`os.urandom`) agar ketiga cipher mengolah data persis sama, (2) timer berpresisi tinggi `time.perf_counter()`, (3) **1 kali *warm-up*** yang tidak dihitung untuk menstabilkan cache CPU, (4) **rata-rata 5 iterasi** pengukuran, dan (5) asersi verifikasi hasil dekripsi sama dengan input asli via SHA-256. Tanpa *hardcoding* angka, tanpa *clamping*, dan tanpa perkalian estimasi.

---

## 5. Cheat Sheet Perintah Terminal (Siap Copy-Paste Saat Demo)

### A. Reset Database & Jalankan Server
```powershell
.\venv\Scripts\python.exe seed_demo.py
.\venv\Scripts\uvicorn.exe app.main:app --reload
```

### B. Inspeksi Langsung Isi `bansos.db` (Bukti Alamat Terenkripsi, IV/Nonce & SHA-256)
Jalankan perintah ini di PowerShell saat demo Bagian 2 untuk memperlihatkan ke dosen bahwa data di SQLite benar-benar terenkripsi:

```powershell
.\venv\Scripts\python.exe -c "import sqlite3; c=sqlite3.connect('bansos.db').cursor(); print('=== ALAMAT TERENKRIPSI DI SQLITE ==='); [print(f'App {r[0]} ({r[1]}): {r[2][:55]}...') for r in c.execute('SELECT id, status, keterangan FROM applications')]; print('=== METADATA DOKUMEN (CIPHER, IV/NONCE, SHA-256) ==='); [print(f'Doc {r[0]} | {r[1]:11s} | IV/Nonce: {r[2][:16]}... | SHA256: {r[3][:16]}...') for r in c.execute('SELECT id, cipher_used, iv_hex, sha256_hash FROM documents LIMIT 6')]"
```

### C. (Opsional) Bukti Cepat Deteksi Kerusakan 1 Byte Ciphertext oleh SHA-256
Jika dosen bertanya bagaimana sistem mendeteksi file `.enc` yang rusak/dimodifikasi (khususnya pada RC4 yang tidak punya error padding):

```powershell
.\venv\Scripts\python.exe -c "from app.crypto_engine import encrypt_rc4, decrypt_rc4, compute_sha256, verify_sha256; import os; data=b'Bukti Video Rumah Warga'; key=os.urandom(16); sha=compute_sha256(data); ct,nonce=encrypt_rc4(data,key); bad=bytearray(ct); bad[5]^=0xFF; pt_bad=decrypt_rc4(bytes(bad),key,nonce); print('Asli cocok SHA-256 :', verify_sha256(decrypt_rc4(ct,key,nonce), sha)); print('Modif 1 byte cocok:', verify_sha256(pt_bad, sha))"
```
