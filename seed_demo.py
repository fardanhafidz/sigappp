"""
seed_demo.py
============
Script reset & seeding database demo SIGAP-PDP menggunakan data realistis Kota Surabaya.
Menghasilkan:
1. Reset bersih bansos.db dan seluruh berkas .enc di storage/encrypted/
2. 1 akun Verifikator Dinsos + 4 akun KPM (password warga: warga123)
3. 3 pengajuan lengkap (Pending, Approved, Rejected) dengan berkas PNG/PDF/DOCX/AVI valid
   yang dienkripsi lewat crypto_engine (AES-256-CBC, DES-CBC, RC4 + Nonce, SHA-256)
4. 4 berkas siap unggah di folder demo_files/ untuk keperluan live demo upload KPM ke-4
"""

import io
import os
import secrets
import struct
import uuid
import zipfile
import zlib
from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import escape

from app.auth import get_password_hash
from app.crypto_engine import (
    compute_sha256,
    encrypt_aes_256_cbc,
    encrypt_des_cbc,
    encrypt_rc4,
    encrypt_text_aes_256_cbc,
    get_user_cipher_key,
)
from app.database import BASE_DIR, DB_PATH, Base, SessionLocal, engine, init_db
from app.models import Application, Document, User

STORAGE_ENCRYPTED_DIR = os.path.join(BASE_DIR, "storage", "encrypted")
DEMO_FILES_DIR = os.path.join(BASE_DIR, "demo_files")

# Mini 5x7 bitmap font (uppercase + digits + basic punctuation) agar PNG e-KTP terbaca jelas
FONT_5X7 = {
    "A": ["01110", "10001", "10001", "11111", "10001", "10001", "10001"],
    "B": ["11110", "10001", "10001", "11110", "10001", "10001", "11110"],
    "C": ["01111", "10000", "10000", "10000", "10000", "10000", "01111"],
    "D": ["11110", "10001", "10001", "10001", "10001", "10001", "11110"],
    "E": ["11111", "10000", "10000", "11110", "10000", "10000", "11111"],
    "F": ["11111", "10000", "10000", "11110", "10000", "10000", "10000"],
    "G": ["01111", "10000", "10000", "10111", "10001", "10001", "01111"],
    "H": ["10001", "10001", "10001", "11111", "10001", "10001", "10001"],
    "I": ["01110", "00100", "00100", "00100", "00100", "00100", "01110"],
    "J": ["00111", "00010", "00010", "00010", "10010", "10010", "01100"],
    "K": ["10001", "10010", "10100", "11000", "10100", "10010", "10001"],
    "L": ["10000", "10000", "10000", "10000", "10000", "10000", "11111"],
    "M": ["10001", "11011", "10101", "10101", "10001", "10001", "10001"],
    "N": ["10001", "11001", "10101", "10011", "10001", "10001", "10001"],
    "O": ["01110", "10001", "10001", "10001", "10001", "10001", "01110"],
    "P": ["11110", "10001", "10001", "11110", "10000", "10000", "10000"],
    "Q": ["01110", "10001", "10001", "10001", "10101", "10010", "01101"],
    "R": ["11110", "10001", "10001", "11110", "10100", "10010", "10001"],
    "S": ["01111", "10000", "10000", "01110", "00001", "00001", "11110"],
    "T": ["11111", "00100", "00100", "00100", "00100", "00100", "00100"],
    "U": ["10001", "10001", "10001", "10001", "10001", "10001", "01110"],
    "V": ["10001", "10001", "10001", "10001", "10001", "01010", "00100"],
    "W": ["10001", "10001", "10001", "10101", "10101", "11011", "10001"],
    "X": ["10001", "10001", "01010", "00100", "01010", "10001", "10001"],
    "Y": ["10001", "10001", "01010", "00100", "00100", "00100", "00100"],
    "Z": ["11111", "00001", "00010", "00100", "01000", "10000", "11111"],
    "0": ["01110", "10011", "10101", "10101", "11001", "10001", "01110"],
    "1": ["00100", "01100", "00100", "00100", "00100", "00100", "01110"],
    "2": ["01110", "10001", "00001", "00110", "01000", "10000", "11111"],
    "3": ["11110", "00001", "00001", "01110", "00001", "00001", "11110"],
    "4": ["00010", "00110", "01010", "10010", "11111", "00010", "00010"],
    "5": ["11111", "10000", "11110", "00001", "00001", "10001", "01110"],
    "6": ["01110", "10000", "11110", "10001", "10001", "10001", "01110"],
    "7": ["11111", "00001", "00010", "00100", "01000", "01000", "01000"],
    "8": ["01110", "10001", "10001", "01110", "10001", "10001", "01110"],
    "9": ["01110", "10001", "10001", "01111", "00001", "00001", "01110"],
    ":": ["00000", "00100", "00100", "00000", "00100", "00100", "00000"],
    "-": ["00000", "00000", "00000", "11111", "00000", "00000", "00000"],
    "/": ["00001", "00010", "00010", "00100", "01000", "01000", "10000"],
    ".": ["00000", "00000", "00000", "00000", "00000", "01100", "01100"],
    ",": ["00000", "00000", "00000", "00000", "00100", "00100", "01000"],
    " ": ["00000", "00000", "00000", "00000", "00000", "00000", "00000"],
}


def _png_chunk(tag: bytes, data: bytes) -> bytes:
    return (
        struct.pack("!I", len(data))
        + tag
        + data
        + struct.pack("!I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    )


def _draw_rect(buf: bytearray, width: int, height: int, x0: int, y0: int, x1: int, y1: int, rgb: tuple[int, int, int]) -> None:
    r, g, b = rgb
    for y in range(max(0, y0), min(height, y1)):
        row_start = y * width * 3
        for x in range(max(0, x0), min(width, x1)):
            idx = row_start + x * 3
            buf[idx] = r
            buf[idx + 1] = g
            buf[idx + 2] = b


def _draw_text(buf: bytearray, width: int, height: int, x0: int, y0: int, text: str, rgb: tuple[int, int, int], scale: int = 2) -> None:
    cursor_x = x0
    for ch in text.upper():
        glyph = FONT_5X7.get(ch, FONT_5X7[" "])
        for row_idx, row_bits in enumerate(glyph):
            for col_idx, bit in enumerate(row_bits):
                if bit == "1":
                    _draw_rect(
                        buf,
                        width,
                        height,
                        cursor_x + col_idx * scale,
                        y0 + row_idx * scale,
                        cursor_x + (col_idx + 1) * scale,
                        y0 + (row_idx + 1) * scale,
                        rgb,
                    )
        cursor_x += 6 * scale


def generate_ktp_png(nama: str, nik: str, alamat: str) -> bytes:
    """Membuat berkas PNG 640x400 valid bergaya pindaian kartu e-KTP/KK menggunakan stdlib."""
    width, height = 640, 400
    buf = bytearray([226, 242, 254] * (width * height))  # latar biru muda e-KTP

    # Bingkai kartu & header biru tua
    _draw_rect(buf, width, height, 0, 0, width, 10, (12, 74, 110))
    _draw_rect(buf, width, height, 0, height - 10, width, height, (12, 74, 110))
    _draw_rect(buf, width, height, 0, 0, 10, height, (12, 74, 110))
    _draw_rect(buf, width, height, width - 10, 0, width, height, (12, 74, 110))
    _draw_rect(buf, width, height, 10, 10, width - 10, 78, (2, 132, 199))

    # Teks header
    _draw_text(buf, width, height, 130, 22, "PROVINSI JAWA TIMUR", (255, 255, 255), scale=3)
    _draw_text(buf, width, height, 185, 50, "KOTA SURABAYA", (224, 242, 254), scale=2)

    # Kotak foto merah + siluet kepala & bahu
    _draw_rect(buf, width, height, 455, 100, 595, 275, (185, 28, 28))
    _draw_rect(buf, width, height, 500, 132, 550, 182, (241, 245, 249))
    _draw_rect(buf, width, height, 478, 194, 572, 275, (30, 41, 59))
    _draw_text(buf, width, height, 466, 290, "SURABAYA", (30, 41, 59), scale=2)
    _draw_text(buf, width, height, 466, 315, "SEUMUR HIDUP", (71, 85, 105), scale=2)

    # Identitas KTP
    _draw_text(buf, width, height, 32, 104, f"NIK   : {nik}", (15, 23, 42), scale=2)
    _draw_text(buf, width, height, 32, 144, f"NAMA  : {nama[:24]}", (15, 23, 42), scale=2)
    _draw_text(buf, width, height, 32, 182, f"ALAMAT: {alamat[:24]}", (30, 41, 59), scale=2)
    _draw_text(buf, width, height, 32, 212, "KOTA  : SURABAYA", (30, 41, 59), scale=2)
    _draw_text(buf, width, height, 32, 244, "AGAMA : INDONESIA / WNI", (51, 65, 85), scale=2)
    _draw_text(buf, width, height, 32, 276, "STAT  : BERKAS DTKS TERENKRIPSI", (2, 132, 199), scale=2)

    # Garis aksen bawah
    _draw_rect(buf, width, height, 32, 324, 420, 328, (148, 163, 184))
    _draw_text(buf, width, height, 32, 342, "DOKUMEN SIMULASI SIGAP-PDP", (71, 85, 105), scale=2)

    # Susun scanlines PNG (filter byte 0 per baris)
    raw = bytearray()
    stride = width * 3
    for y in range(height):
        raw.append(0)
        start = y * stride
        raw.extend(buf[start : start + stride])

    ihdr = struct.pack("!IIBBBBB", width, height, 8, 2, 0, 0, 0)
    idat = zlib.compress(bytes(raw), level=6)
    return b"".join([
        b"\x89PNG\r\n\x1a\n",
        _png_chunk(b"IHDR", ihdr),
        _png_chunk(b"IDAT", idat),
        _png_chunk(b"IEND", b""),
    ])


def _pdf_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def generate_sktm_pdf(nama: str, nik: str, alamat: str, keterangan_ekonomi: str) -> bytes:
    """Membuat dokumen PDF 1.4 valid berisi Surat Keterangan Tidak Mampu (SKTM)."""
    lines = [
        (72, 760, 14, True, "PEMERINTAH KOTA SURABAYA"),
        (72, 742, 11, True, "KELURAHAN KEPUTIH - KECAMATAN SUKOLILO"),
        (72, 710, 13, True, "SURAT KETERANGAN TIDAK MAMPU (SKTM)"),
        (72, 692, 10, False, "Nomor: 474/108/436.9.20/2026"),
        (72, 660, 11, False, "Yang bertanda tangan di bawah ini Lurah menerangkan bahwa:"),
        (90, 634, 11, False, f"Nama Lengkap     : {nama}"),
        (90, 616, 11, False, f"NIK Kependudukan : {nik}"),
        (90, 598, 11, False, f"Alamat Domisili  : {alamat[:68]}"),
        (90, 580, 11, False, f"Keterangan       : {keterangan_ekonomi[:68]}"),
        (72, 544, 11, False, "Warga tersebut benar berdomisili di wilayah Kota Surabaya dan"),
        (72, 526, 11, False, "tergolong keluarga prasejahtera untuk pengajuan Bantuan Sosial."),
        (72, 490, 10, False, "Dilindungi berdasarkan UU No. 27 Tahun 2022 (UU PDP)."),
        (360, 430, 10, False, "Surabaya, 2026"),
        (360, 412, 10, True, "Petugas Kelurahan / Verifikator"),
        (360, 365, 10, False, "( Tanda Tangan Resmi )"),
    ]

    stream_cmds = ["0.75 w 72 728 m 523 728 l S"]
    for x, y, size, bold, text in lines:
        font = "/F2" if bold else "/F1"
        stream_cmds.append(f"BT {font} {size} Tf {x} {y} Td ({_pdf_escape(text)}) Tj ET")
    stream_bytes = "\n".join(stream_cmds).encode("latin-1", errors="replace")

    objects = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        (
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            b"/Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>\nendobj\n"
        ),
        b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
        b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n",
        (
            f"6 0 obj\n<< /Length {len(stream_bytes)} >>\nstream\n".encode("ascii")
            + stream_bytes
            + b"\nendstream\nendobj\n"
        ),
    ]

    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(out))
        out.extend(obj)

    xref_pos = len(out)
    out.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    out.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        out.extend(f"{off:010d} 00000 n \n".encode("ascii"))

    out.extend(
        f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("ascii")
    )
    return bytes(out)


def generate_berita_acara_docx(nama: str, nik: str, alamat: str, catatan_survei: str) -> bytes:
    """Membuat berkas OOXML .docx valid berisi Berita Acara Survei Lapangan DTKS."""
    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"""

    rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""

    paragraphs = [
        "BERITA ACARA SURVEI LAPANGAN VERIFIKASI DTKS",
        "DINAS SOSIAL KOTA SURABAYA - SISTEM SIGAP-PDP",
        "------------------------------------------------------------",
        f"Nama Pemohon (KPM) : {nama}",
        f"NIK                : {nik}",
        f"Alamat Domisili    : {alamat}",
        "Jenis Enkripsi     : DES-CBC (Kompatibilitas Arsip Legacy Pemda)",
        "------------------------------------------------------------",
        "HASIL OBSERVASI & VERIFIKASI FAKTUAL:",
        catatan_survei,
        "",
        "Berita acara ini dibuat dengan sebenar-benarnya sebagai lampiran resmi",
        "penetapan kelayakan bantuan sosial daerah.",
        "",
        "Mengetahui,                               Petugas Survei Lapangan,",
        "Ketua RT Setempat                         Dinas Sosial Kota Surabaya",
    ]

    body_xml = "\n".join(
        f'    <w:p><w:r><w:t xml:space="preserve">{escape(line)}</w:t></w:r></w:p>'
        for line in paragraphs
    )

    document_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
{body_xml}
    <w:sectPr><w:pgSz w:w="11906" w:h="16838"/></w:sectPr>
  </w:body>
</w:document>"""

    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("word/document.xml", document_xml)
    return bio.getvalue()


def generate_house_video_avi(seed_variant: int = 0) -> bytes:
    """
    Membuat video AVI 24-bit uncompressed (160x120, 15 frame @ 5 fps = 3 detik, ~864 KB)
    bergaya cuplikan survei rumah yang dapat diputar langsung di VLC / Windows Media Player.
    """
    width, height = 160, 120
    num_frames = 15
    fps = 5
    frame_size = width * height * 3

    frames = []
    for f_idx in range(num_frames):
        pan = (f_idx * 6 + seed_variant * 15) % 80
        frame = bytearray(frame_size)
        for y in range(height):
            row_offset = y * width * 3
            for x in range(width):
                # Format AVI BGR bottom-up: y=0 di bawah, y=119 di atas
                if y < 28:
                    # Tanah / jalan
                    b, g, r = 90, 105, 115
                elif 28 <= y < 78 and (32 + pan // 3) <= x <= (112 + pan // 3):
                    # Dinding rumah + pintu & jendela
                    in_door = (56 + pan // 3) <= x <= (72 + pan // 3) and y < 58
                    in_win = (82 + pan // 3) <= x <= (100 + pan // 3) and 44 <= y <= 62
                    if in_door:
                        b, g, r = 45, 70, 110
                    elif in_win:
                        b, g, r = 240, 210, 150
                    else:
                        b, g, r = 215, 225, 232
                elif 78 <= y < 98 and (24 + pan // 3 + (y - 78)) <= x <= (120 + pan // 3 - (y - 78)):
                    # Atap rumah segitiga
                    b, g, r = 55, 80, 165
                else:
                    # Langit biru cerah
                    b, g, r = 245, 200 - (y // 3), 135

                idx = row_offset + x * 3
                frame[idx] = b
                frame[idx + 1] = g
                frame[idx + 2] = r
        frames.append(bytes(frame))

    # Bangun sub-chunk strl
    strh = struct.pack(
        "<4s4sIHHIIIIIIII4h",
        b"vids",
        b"DIB ",
        0,
        0,
        0,
        0,
        1,
        fps,
        0,
        num_frames,
        frame_size,
        0xFFFFFFFF,
        0,
        0,
        0,
        width,
        height,
    )
    strf = struct.pack(
        "<IiiHHIIiiII",
        40,
        width,
        height,
        1,
        24,
        0,
        frame_size,
        0,
        0,
        0,
        0,
    )
    strl_body = b"strl" + b"strh" + struct.pack("<I", len(strh)) + strh + b"strf" + struct.pack("<I", len(strf)) + strf
    strl_list = b"LIST" + struct.pack("<I", len(strl_body)) + strl_body

    avih = struct.pack(
        "<IIIIIIIIIIIIII",
        1_000_000 // fps,
        frame_size * fps,
        0,
        0x10,
        num_frames,
        0,
        1,
        frame_size,
        width,
        height,
        0,
        0,
        0,
        0,
    )
    hdrl_body = b"hdrl" + b"avih" + struct.pack("<I", len(avih)) + avih + strl_list
    hdrl_list = b"LIST" + struct.pack("<I", len(hdrl_body)) + hdrl_body

    movi_chunks = bytearray(b"movi")
    idx1_entries = bytearray()
    offset = 4
    for frame in frames:
        movi_chunks.extend(b"00db")
        movi_chunks.extend(struct.pack("<I", len(frame)))
        movi_chunks.extend(frame)
        idx1_entries.extend(struct.pack("<4sIII", b"00db", 0x10, offset, len(frame)))
        offset += 8 + len(frame)

    movi_list = b"LIST" + struct.pack("<I", len(movi_chunks)) + bytes(movi_chunks)
    idx1_chunk = b"idx1" + struct.pack("<I", len(idx1_entries)) + bytes(idx1_entries)

    riff_body = b"AVI " + hdrl_list + movi_list + idx1_chunk
    return b"RIFF" + struct.pack("<I", len(riff_body)) + riff_body


def reset_storage_and_db() -> None:
    """Menghapus data database lama dan seluruh berkas .enc lalu menginisialisasi ulang DB."""
    engine.dispose()
    if os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
        except PermissionError:
            # Jika file bansos.db sedang dibuka proses lain (mis. viewer/editor), drop seluruh tabel secara bersih
            Base.metadata.drop_all(bind=engine)

    os.makedirs(STORAGE_ENCRYPTED_DIR, exist_ok=True)
    for fname in os.listdir(STORAGE_ENCRYPTED_DIR):
        if fname.endswith(".enc"):
            os.remove(os.path.join(STORAGE_ENCRYPTED_DIR, fname))

    init_db()


def seed_realistic_demo() -> None:
    reset_storage_and_db()
    os.makedirs(DEMO_FILES_DIR, exist_ok=True)

    db = SessionLocal()
    try:
        demo_users = [
            {
                "nik": "3578011508850001",
                "nama": "Siti Aminah",
                "alamat": "Jl. Keputih Tegal Timur No. 14, RT 03/RW 02, Kec. Sukolilo, Surabaya - Pengajuan PKH Lansia & Sembako",
                "status": "Pending",
                "notes": None,
                "days_ago": 1,
                "ekonomi": "Pedagang sayur keliling, penghasilan tidak tetap di bawah UMR.",
                "survei": "Rumah semi permanen ukuran 4x6m bersama 2 tanggungan lansia. Layak verifikasi lanjutan.",
                "variant": 1,
            },
            {
                "nik": "3578022405790002",
                "nama": "Slamet Raharjo",
                "alamat": "Jl. Gebang Lor No. 27, RT 01/RW 04, Kec. Sukolilo, Surabaya - Bantuan Modal Usaha Mikro",
                "status": "Approved",
                "notes": "Hasil survei lapangan terverifikasi: kondisi tempat tinggal sesuai dan layak menerima bantuan modal usaha mikro.",
                "days_ago": 3,
                "ekonomi": "Penjahit rumahan dengan 3 anak usia sekolah.",
                "survei": "Kondisi hunian atap asbes bocor dan peralatan kerja terbatas. Direkomendasikan disetujui.",
                "variant": 2,
            },
            {
                "nik": "3578031103910003",
                "nama": "Hendra Wijaya",
                "alamat": "Jl. Mulyosari Timur Blok B-9, RT 05/RW 03, Kec. Mulyorejo, Surabaya - Bantuan Perbaikan Rumah",
                "status": "Rejected",
                "notes": "Berkas rumah dan penghasilan tidak memenuhi ambang batas kriteria DTKS setelah pengecekan lapangan.",
                "days_ago": 5,
                "ekonomi": "Karyawan swasta kontrak dengan aset kendaraan bermotor roda empat.",
                "survei": "Hasil survei menunjukkan kondisi hunian permanen layak huni dan penghasilan di atas batas DTKS.",
                "variant": 3,
            },
            {
                "nik": "3578040912880004",
                "nama": "Rina Kusumawati",
                "alamat": None,
                "status": None,
                "notes": None,
                "days_ago": 0,
                "ekonomi": "Penjual jajanan pasar tradisional, kepala keluarga tunggal.",
                "survei": "Berita acara survei awal RT/RW untuk pengajuan baru bantuan sosial.",
                "variant": 4,
            },
        ]

        created_apps = 0
        created_docs = 0

        for item in demo_users:
            kdf_salt = secrets.token_hex(16)
            user = User(
                nik=item["nik"],
                nama=item["nama"],
                hashed_password=get_password_hash("warga123"),
                kdf_salt=kdf_salt,
                role="kpm",
            )
            db.add(user)
            db.flush()

            # Buat 4 file valid untuk user ini
            slug = item["nama"].replace(" ", "_")
            ktp_bytes = generate_ktp_png(item["nama"], item["nik"], item["alamat"] or "Jl. Klampis Harapan No. 8, Kec. Sukolilo, Surabaya")
            sktm_bytes = generate_sktm_pdf(item["nama"], item["nik"], item["alamat"] or "Jl. Klampis Harapan No. 8, Kec. Sukolilo, Surabaya", item["ekonomi"])
            ba_bytes = generate_berita_acara_docx(item["nama"], item["nik"], item["alamat"] or "Jl. Klampis Harapan No. 8, Kec. Sukolilo, Surabaya", item["survei"])
            vid_bytes = generate_house_video_avi(item["variant"])

            # Untuk Rina Kusumawati (KPM 4), simpan file ke demo_files/ agar siap diuji unggah live
            if item["status"] is None:
                demo_map = {
                    f"KTP_KK_{slug}.png": ktp_bytes,
                    f"SKTM_{slug}.pdf": sktm_bytes,
                    "Berita_Acara_Survei_Rina.docx": ba_bytes,
                    "Video_Kondisi_Rumah_Rina.avi": vid_bytes,
                }
                for fname, raw in demo_map.items():
                    with open(os.path.join(DEMO_FILES_DIR, fname), "wb") as f_demo:
                        f_demo.write(raw)
                continue

            aes_key = get_user_cipher_key(user.nik, user.kdf_salt, "AES-256-CBC")
            des_key = get_user_cipher_key(user.nik, user.kdf_salt, "DES-CBC")
            rc4_key = get_user_cipher_key(user.nik, user.kdf_salt, "RC4")

            created_ts = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=item["days_ago"])
            app_obj = Application(
                nomor_pengajuan=f"BANSOS-{created_ts.strftime('%Y%m%d')}-{secrets.token_hex(3).upper()}",
                user_id=user.id,
                keterangan=encrypt_text_aes_256_cbc(item["alamat"], aes_key),
                status=item["status"],
                verifikator_notes=item["notes"],
                created_at=created_ts,
                updated_at=created_ts,
            )
            db.add(app_obj)
            db.flush()
            created_apps += 1

            specs = [
                ("ktp_kk", "Pindaian KTP / KK", f"KTP_KK_{slug}.png", "image/png", "AES-256-CBC", ktp_bytes),
                ("slip_gaji", "Slip Gaji / SKTM", f"SKTM_{slug}.pdf", "application/pdf", "AES-256-CBC", sktm_bytes),
                (
                    "berita_acara",
                    "Berita Acara Survei",
                    f"Berita_Acara_{slug}.docx",
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "DES-CBC",
                    ba_bytes,
                ),
                ("video_rumah", "Video Kondisi Rumah", f"Video_Rumah_{slug}.avi", "video/x-msvideo", "RC4", vid_bytes),
            ]

            for cat, cat_label, orig_name, mime, cipher_name, raw_bytes in specs:
                file_id = str(uuid.uuid4())
                sha_hex = compute_sha256(raw_bytes)
                if cipher_name == "AES-256-CBC":
                    ct, iv = encrypt_aes_256_cbc(raw_bytes, aes_key)
                    iv_hex = iv.hex()
                elif cipher_name == "DES-CBC":
                    ct, iv = encrypt_des_cbc(raw_bytes, des_key)
                    iv_hex = iv.hex()
                else:
                    ct, nonce = encrypt_rc4(raw_bytes, rc4_key)
                    iv_hex = nonce.hex()

                disk_name = f"{file_id}.enc"
                with open(os.path.join(STORAGE_ENCRYPTED_DIR, disk_name), "wb") as f_enc:
                    f_enc.write(ct)

                db.add(
                    Document(
                        file_id=file_id,
                        application_id=app_obj.id,
                        user_id=user.id,
                        category=cat,
                        category_label=cat_label,
                        original_filename=orig_name,
                        mime_type=mime,
                        cipher_used=cipher_name,
                        iv_hex=iv_hex,
                        sha256_hash=sha_hex,
                        file_size=len(raw_bytes),
                        file_path=os.path.join("storage", "encrypted", disk_name),
                        created_at=created_ts,
                    )
                )
                created_docs += 1

        db.commit()
        print(f"[OK] Seeding selesai: 1 Verifikator + {len(demo_users)} KPM + {created_apps} Pengajuan + {created_docs} Dokumen (.enc).")
        print(f"[OK] Berkas demo siap unggah tersedia di: {DEMO_FILES_DIR}")
    finally:
        db.close()


if __name__ == "__main__":
    seed_realistic_demo()
