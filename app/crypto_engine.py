"""
app/crypto_engine.py
====================
Modul Logika Kriptografi untuk SIGAP-PDP (Sistem Integrasi Bansos Tanggap Perlindungan Data Pribadi).

Prinsip Keamanan yang Diterapkan:
1. Pemisahan Rahasia Kunci: Kunci per pengguna diturunkan dengan PBKDF2-HMAC-SHA256
   (100.000 iterasi) dari APP_MASTER_KEY (di luar database) + NIK + salt unik per akun.
2. Mode ECB Dilarang Keras: Cipher blok AES-256 dan DES wajib memakai mode CBC + PKCS#7 padding
   dengan Initialization Vector (IV) acak unik per berkas/record.
3. Proteksi RC4 terhadap Keystream Reuse: Setiap berkas RC4 memakai nonce acak 16-byte unik
   sehingga kunci efektif per berkas berbeda walau pengguna atau isi berkas sama.
4. Enkripsi Data Pribadi Teks: Alamat domisili/keterangan di SQLite turut dienkripsi AES-256-CBC.
5. Verifikasi Keutuhan (Lossless Integrity): Setiap berkas dicatat sidik jari SHA-256 sebelum
   dienkripsi dan divalidasi ulang saat didekripsi menggunakan perbandingan constant-time.
"""

import os
import hmac
import time
import hashlib
import platform
from typing import Tuple, Dict, Any, List

try:
    import Cryptodome
    from Cryptodome.Cipher import AES, DES, ARC4
    from Cryptodome.Util.Padding import pad, unpad
except ImportError:
    try:
        import Crypto as Cryptodome
        from Crypto.Cipher import AES, DES, ARC4
        from Crypto.Util.Padding import pad, unpad
    except ImportError:
        raise ImportError(
            "Library kriptografi tidak ditemukan. Pasang pycryptodomex: pip install pycryptodomex"
        )


# Master Key disimpan terpisah dari database SQLite (via environment variable / fallback demo)
APP_MASTER_KEY = os.getenv("SIGAPP_MASTER_KEY", "sigapp-pdp-master-key-keamanan-informasi-2026")
KDF_ITERATIONS = 100_000
ENC_TEXT_PREFIX = "ENC:AES256CBC:"


# 1. KEY DERIVATION FUNCTION (PBKDF2-HMAC-SHA256)
def derive_key(secret: str | bytes, salt: bytes, length: int = 32) -> bytes:
    """
    Menurunkan kunci enkripsi biner menggunakan PBKDF2-HMAC-SHA256 (100.000 iterasi).
    """
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    return hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=secret,
        salt=salt,
        iterations=KDF_ITERATIONS,
        dklen=length,
    )


def get_user_cipher_key(user_nik: str, salt_hex: str, cipher_type: str) -> bytes:
    """
    Menghasilkan kunci kriptografi unik per pengguna dan jenis cipher:
    - Master key berada di luar database agar kebocoran DB + file .enc tidak langsung membuka data.
    - Panjang kunci: 32 byte (AES-256), 8 byte (DES), 16 byte (RC4 base key).
    """
    salt_bytes = bytes.fromhex(salt_hex)
    secret = f"{APP_MASTER_KEY}:{user_nik}"
    cipher_upper = cipher_type.upper()

    if "AES" in cipher_upper:
        return derive_key(secret, salt_bytes, length=32)
    if "DES" in cipher_upper:
        return derive_key(secret, salt_bytes, length=8)
    if "RC4" in cipher_upper:
        return derive_key(secret, salt_bytes, length=16)
    return derive_key(secret, salt_bytes, length=32)


# 2. AES-256-CBC (Advanced Encryption Standard)
def encrypt_aes_256_cbc(data: bytes, key: bytes, iv: bytes | None = None) -> Tuple[bytes, bytes]:
    """Enkripsi biner dengan AES-256 mode CBC + PKCS#7 padding dan IV acak 16 byte."""
    if len(key) != 32:
        raise ValueError(f"AES-256 membutuhkan kunci 32 bytes, diterima {len(key)} bytes.")
    if iv is None:
        iv = os.urandom(16)
    elif len(iv) != 16:
        raise ValueError(f"AES membutuhkan IV 16 bytes, diterima {len(iv)} bytes.")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size, style="pkcs7"))
    return ciphertext, iv


def decrypt_aes_256_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Dekripsi ciphertext AES-256-CBC dan melepas PKCS#7 padding."""
    if len(key) != 32:
        raise ValueError(f"AES-256 membutuhkan kunci 32 bytes, diterima {len(key)} bytes.")
    if len(iv) != 16:
        raise ValueError(f"AES membutuhkan IV 16 bytes, diterima {len(iv)} bytes.")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size, style="pkcs7")


# 3. DES-CBC (Data Encryption Standard - Legacy Interoperability)
def encrypt_des_cbc(data: bytes, key: bytes, iv: bytes | None = None) -> Tuple[bytes, bytes]:
    """Enkripsi biner dengan DES mode CBC + PKCS#7 padding dan IV acak 8 byte."""
    if len(key) != 8:
        raise ValueError(f"DES membutuhkan kunci 8 bytes, diterima {len(key)} bytes.")
    if iv is None:
        iv = os.urandom(8)
    elif len(iv) != 8:
        raise ValueError(f"DES membutuhkan IV 8 bytes, diterima {len(iv)} bytes.")

    cipher = DES.new(key, DES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, DES.block_size, style="pkcs7"))
    return ciphertext, iv


def decrypt_des_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Dekripsi ciphertext DES-CBC dan melepas PKCS#7 padding."""
    if len(key) != 8:
        raise ValueError(f"DES membutuhkan kunci 8 bytes, diterima {len(key)} bytes.")
    if len(iv) != 8:
        raise ValueError(f"DES membutuhkan IV 8 bytes, diterima {len(iv)} bytes.")

    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), DES.block_size, style="pkcs7")


# 4. RC4 STREAM CIPHER DENGAN PER-FILE NONCE
def derive_rc4_file_key(base_key: bytes, nonce: bytes) -> bytes:
    """Menggabungkan base key pengguna dengan nonce acak 16-byte agar keystream tidak pernah berulang."""
    return hashlib.sha256(base_key + nonce).digest()[:16]


def encrypt_rc4(data: bytes, key: bytes, nonce: bytes | None = None) -> Tuple[bytes, bytes]:
    """
    Enkripsi stream RC4 menggunakan nonce acak 16 byte per berkas.
    Mencegah keystream reuse (C1 XOR C2 = P1 XOR P2) jika berkas diunggah ulang.
    """
    if nonce is None:
        nonce = os.urandom(16)
    elif len(nonce) != 16:
        raise ValueError(f"RC4 nonce harus 16 bytes, diterima {len(nonce)} bytes.")

    file_key = derive_rc4_file_key(key, nonce)
    cipher = ARC4.new(file_key)
    return cipher.encrypt(data), nonce


def decrypt_rc4(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """Dekripsi stream RC4 menggunakan base key pengguna dan nonce berkas."""
    if len(nonce) != 16:
        raise ValueError(f"RC4 nonce harus 16 bytes, diterima {len(nonce)} bytes.")

    file_key = derive_rc4_file_key(key, nonce)
    cipher = ARC4.new(file_key)
    return cipher.decrypt(ciphertext)


# 5. ENKRIPSI DATA PRIBADI TEKS DI DATABASE (AES-256-CBC)
def encrypt_text_aes_256_cbc(plaintext: str, key: bytes) -> str:
    """Mengenkripsi teks pribadi (alamat/keterangan) menjadi string berawalan ENC:AES256CBC:."""
    if not plaintext:
        return ""
    ct, iv = encrypt_aes_256_cbc(plaintext.encode("utf-8"), key)
    return f"{ENC_TEXT_PREFIX}{iv.hex()}:{ct.hex()}"


def decrypt_text_aes_256_cbc(stored: str | None, key: bytes) -> str:
    """Mendekripsi teks terenkripsi dari database. Plaintext lama tetap dikembalikan apa adanya."""
    if not stored:
        return ""
    if not stored.startswith(ENC_TEXT_PREFIX):
        return stored
    try:
        payload = stored[len(ENC_TEXT_PREFIX):]
        iv_hex, ct_hex = payload.split(":", 1)
        plain_bytes = decrypt_aes_256_cbc(bytes.fromhex(ct_hex), key, bytes.fromhex(iv_hex))
        return plain_bytes.decode("utf-8")
    except Exception:
        return "[Gagal mendekripsi data]"


# 6. VERIFIKASI KEUTUHAN DATA (SHA-256)
def compute_sha256(data: bytes) -> str:
    """Menghitung hash SHA-256 heksadesimal untuk verifikasi integritas lossless."""
    return hashlib.sha256(data).hexdigest()


def verify_sha256(data: bytes, expected_hex: str | None) -> bool:
    """Memverifikasi integritas data hasil dekripsi terhadap hash SHA-256 tersimpan."""
    if not expected_hex:
        return True
    actual_hex = compute_sha256(data)
    return hmac.compare_digest(actual_hex, expected_hex)


# 7. INFORMASI LINGKUNGAN & BENCHMARK KOMPARATIF YANG ANDAL
def get_crypto_environment() -> Dict[str, str]:
    """Mengembalikan informasi runtime Python dan PyCryptodome secara jujur."""
    pycrypto_ver = getattr(Cryptodome, "__version__", "3.x")
    return {
        "python_version": platform.python_version(),
        "pycryptodome_version": pycrypto_ver,
        "os_info": f"{platform.system()} {platform.release()}",
        "machine": platform.machine() or "x86_64",
    }


def _measure_cipher_once(cipher_name: str, data: bytes) -> Tuple[float, float, int, bool]:
    """Helper menjalankan 1 siklus enkripsi + dekripsi terukur untuk benchmark."""
    if cipher_name == "AES-256-CBC":
        key = os.urandom(32)
        t0 = time.perf_counter()
        ct, iv = encrypt_aes_256_cbc(data, key)
        t_enc = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        pt = decrypt_aes_256_cbc(ct, key, iv)
        t_dec = (time.perf_counter() - t0) * 1000

    elif cipher_name == "DES-CBC":
        key = os.urandom(8)
        t0 = time.perf_counter()
        ct, iv = encrypt_des_cbc(data, key)
        t_enc = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        pt = decrypt_des_cbc(ct, key, iv)
        t_dec = (time.perf_counter() - t0) * 1000

    elif cipher_name == "RC4":
        key = os.urandom(16)
        t0 = time.perf_counter()
        ct, nonce = encrypt_rc4(data, key)
        t_enc = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        pt = decrypt_rc4(ct, key, nonce)
        t_dec = (time.perf_counter() - t0) * 1000
    else:
        raise ValueError(f"Cipher tidak dikenal: {cipher_name}")

    overhead = len(ct) - len(data)
    ok = (pt == data) and (compute_sha256(pt) == compute_sha256(data))
    return t_enc, t_dec, overhead, ok


def benchmark_ciphers(data_size_kb: int = 1024, iterations: int = 5) -> Dict[str, Any]:
    """
    Membandingkan AES-256-CBC, DES-CBC, dan RC4 secara apple-to-apple pada payload identik.
    Setiap cipher menjalani 1 kali warm-up (tidak dihitung) diikuti `iterations` kali
    pengukuran rata-rata menggunakan `time.perf_counter()`, plus verifikasi integritas SHA-256.
    """
    data = os.urandom(data_size_kb * 1024)
    size_mb = len(data) / (1024 * 1024)
    size_label = f"{data_size_kb // 1024} MB" if data_size_kb >= 1024 and data_size_kb % 1024 == 0 else f"{data_size_kb} KB"

    cipher_specs = [
        {
            "key": "AES-256-CBC",
            "cipher": "AES-256-CBC",
            "badge_type": "aes",
            "key_size_bits": 256,
            "block_info": "Blok 16 B • PKCS#7 + IV 16 B",
            "security_level": "Tinggi (Standar UU PDP)",
            "use_case": "Data Pribadi, KTP/KK, SKTM",
        },
        {
            "key": "DES-CBC",
            "cipher": "DES-CBC",
            "badge_type": "des",
            "key_size_bits": 64,
            "block_info": "Blok 8 B • PKCS#7 + IV 8 B",
            "security_level": "Rendah (56-bit efektif • Legacy)",
            "use_case": "Kompatibilitas Arsip Pemda Lama",
        },
        {
            "key": "RC4",
            "cipher": "RC4 + Nonce",
            "badge_type": "rc4",
            "key_size_bits": 128,
            "block_info": "Stream (1 B) • Nonce 16 B",
            "security_level": "Terbatas / Deprecated (RFC 7465)",
            "use_case": "Payload Video Besar (High Throughput)",
        },
    ]

    entries: List[Dict[str, Any]] = []
    for spec in cipher_specs:
        # 1 warm-up agar cache CPU dan alokasi Python stabil
        _measure_cipher_once(spec["key"], data)

        enc_times = []
        dec_times = []
        overhead_bytes = 0
        all_ok = True

        for _ in range(iterations):
            t_enc, t_dec, overhead, ok = _measure_cipher_once(spec["key"], data)
            enc_times.append(t_enc)
            dec_times.append(t_dec)
            overhead_bytes = overhead
            all_ok = all_ok and ok

        assert all_ok, f"Verifikasi integritas gagal saat benchmark {spec['key']}"

        avg_enc_ms = sum(enc_times) / iterations
        avg_dec_ms = sum(dec_times) / iterations
        enc_mbps = size_mb / (avg_enc_ms / 1000.0) if avg_enc_ms > 0 else 0.0
        dec_mbps = size_mb / (avg_dec_ms / 1000.0) if avg_dec_ms > 0 else 0.0
        avg_mbps = (enc_mbps + dec_mbps) / 2.0

        entries.append({
            "key": spec["key"],
            "cipher": spec["cipher"],
            "badge_type": spec["badge_type"],
            "key_size_bits": spec["key_size_bits"],
            "block_info": spec["block_info"],
            "encrypt_time_ms": round(avg_enc_ms, 3),
            "decrypt_time_ms": round(avg_dec_ms, 3),
            "encrypt_speed_mbps": round(enc_mbps, 2),
            "decrypt_speed_mbps": round(dec_mbps, 2),
            "avg_speed_mbps": round(avg_mbps, 2),
            "overhead_bytes": overhead_bytes,
            "integrity_ok": all_ok,
            "security_level": spec["security_level"],
            "use_case": spec["use_case"],
        })

    by_key = {e["key"]: e for e in entries}
    fastest = max(entries, key=lambda e: e["avg_speed_mbps"])
    slowest = min(entries, key=lambda e: e["avg_speed_mbps"])

    des_speed = by_key["DES-CBC"]["avg_speed_mbps"] or 1.0
    rc4_vs_des = round(by_key["RC4"]["avg_speed_mbps"] / des_speed, 2)
    aes_vs_des = round(by_key["AES-256-CBC"]["avg_speed_mbps"] / des_speed, 2)

    # Skala grafik perbandingan speed & waktu eksekusi (+15% headroom atas agar tidak menyentuh plafon)
    raw_max_speed = max(max(e["encrypt_speed_mbps"], e["decrypt_speed_mbps"]) for e in entries) or 1.0
    chart_max_speed = round(raw_max_speed * 1.15, 1)
    raw_max_time = max(max(e["encrypt_time_ms"], e["decrypt_time_ms"]) for e in entries) or 1.0
    chart_max_time = round(raw_max_time * 1.15, 2)

    for e in entries:
        e["enc_speed_pct"] = round(max(4.0, min(100.0, (e["encrypt_speed_mbps"] / chart_max_speed) * 100.0)), 1)
        e["dec_speed_pct"] = round(max(4.0, min(100.0, (e["decrypt_speed_mbps"] / chart_max_speed) * 100.0)), 1)
        e["enc_time_pct"] = round(max(4.0, min(100.0, (e["encrypt_time_ms"] / chart_max_time) * 100.0)), 1)
        e["dec_time_pct"] = round(max(4.0, min(100.0, (e["decrypt_time_ms"] / chart_max_time) * 100.0)), 1)

    return {
        "environment": get_crypto_environment(),
        "data_size_kb": data_size_kb,
        "data_size_label": size_label,
        "iterations": iterations,
        "entries": entries,
        "by_key": by_key,
        "chart": {
            "max_speed_mbps": chart_max_speed,
            "speed_ticks": [
                round(chart_max_speed, 0),
                round(chart_max_speed * 0.75, 0),
                round(chart_max_speed * 0.5, 0),
                round(chart_max_speed * 0.25, 0),
                0,
            ],
            "max_time_ms": chart_max_time,
            "time_ticks": [
                round(chart_max_time, 2),
                round(chart_max_time * 0.75, 2),
                round(chart_max_time * 0.5, 2),
                round(chart_max_time * 0.25, 2),
                0,
            ],
        },
        "summary": {
            "fastest_cipher": fastest["cipher"],
            "fastest_speed_mbps": fastest["avg_speed_mbps"],
            "slowest_cipher": slowest["cipher"],
            "slowest_speed_mbps": slowest["avg_speed_mbps"],
            "rc4_vs_des_ratio": rc4_vs_des,
            "aes_vs_des_ratio": aes_vs_des,
        },
    }


def run_bansos_scenarios_benchmark(iterations: int = 3) -> Tuple[list, str]:
    """
    Menjalankan 4 skenario ukuran data nyata SIGAP-PDP secara jujur (tanpa clamping
    atau perkalian estimasi) dengan 1 warm-up dan rata-rata `iterations` kali eksekusi.
    """
    scenario_specs = [
        {
            "name": "Data Pribadi / Alamat (50 KB)",
            "desc": "Payload Teks Identitas & Domisili (UU PDP)",
            "cipher_key": "AES-256-CBC",
            "cipher": "AES-256-CBC",
            "cipher_sub": "",
            "cipher_badge_type": "aes",
            "size_bytes": 50 * 1024,
        },
        {
            "name": "Pindaian KTP & KK (1 MB)",
            "desc": "Dokumen Citra / PDF Identitas Kependudukan",
            "cipher_key": "AES-256-CBC",
            "cipher": "AES-256-CBC",
            "cipher_sub": "",
            "cipher_badge_type": "aes",
            "size_bytes": 1 * 1024 * 1024,
        },
        {
            "name": "Berita Acara Survei (2 MB)",
            "desc": "Dokumen Perkantoran / Arsip Legacy Pemda",
            "cipher_key": "DES-CBC",
            "cipher": "DES-CBC",
            "cipher_sub": "(Legacy)",
            "cipher_badge_type": "des",
            "size_bytes": 2 * 1024 * 1024,
        },
        {
            "name": "Video Kondisi Hunian (5 MB)",
            "desc": "Rekaman Bukti Fisik Lapangan (Stream Media)",
            "cipher_key": "RC4",
            "cipher": "RC4",
            "cipher_sub": "(+ Nonce)",
            "cipher_badge_type": "rc4",
            "size_bytes": 5 * 1024 * 1024,
        },
    ]

    scenarios = []
    for spec in scenario_specs:
        payload = os.urandom(spec["size_bytes"])
        size_mb = len(payload) / (1024 * 1024)

        # 1 warm-up
        _measure_cipher_once(spec["cipher_key"], payload)

        enc_list = []
        dec_list = []
        for _ in range(iterations):
            t_enc, t_dec, _, ok = _measure_cipher_once(spec["cipher_key"], payload)
            assert ok, f"Integrity error on scenario {spec['name']}"
            enc_list.append(t_enc)
            dec_list.append(t_dec)

        avg_enc = sum(enc_list) / iterations
        avg_dec = sum(dec_list) / iterations
        avg_sec = (avg_enc + avg_dec) / 2000.0
        tp = round(size_mb / avg_sec, 2) if avg_sec > 0 else 0.0

        scenarios.append({
            "name": spec["name"],
            "desc": spec["desc"],
            "cipher": spec["cipher"],
            "cipher_sub": spec["cipher_sub"],
            "cipher_badge_type": spec["cipher_badge_type"],
            "enc_time_ms": f"{avg_enc:.2f} ms",
            "dec_time_ms": f"{avg_dec:.2f} ms",
            "throughput": f"{tp:.2f} MB/s",
        })

    current_time_str = time.strftime("%d %b %Y, %H:%M WIB")
    return scenarios, current_time_str
