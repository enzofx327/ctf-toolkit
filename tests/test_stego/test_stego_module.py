"""
Test suite for the Steganography module.
"""

import struct
import zlib
import pytest
from pathlib import Path

from ctf_toolkit.modules.stego.stego_module import (
    StegoModule,
    _detect_magic,
    _png_pixels,
    MAGIC_DB,
)


@pytest.fixture
def stego():
    return StegoModule()


def _make_png_with_lsb(message: bytes, width: int = 100, height: int = 100) -> bytes:
    """
    Build a minimal PNG with message hidden in LSB of red channel.
    """
    import zlib
    import struct

    channels = 3  # RGB
    pixels = bytearray(width * height * channels)

    # Embed message bits into LSB of pixel[0] red channel bytes
    bit_idx = 0
    for byte_val in message:
        for bit_pos in range(7, -1, -1):
            if bit_idx >= len(pixels):
                break
            bit = (byte_val >> bit_pos) & 1
            pixels[bit_idx] = (pixels[bit_idx] & 0xFE) | bit
            bit_idx += channels  # step through R bytes only

    # Build raw image data (filter byte 0 + row data)
    raw_rows = bytearray()
    for row in range(height):
        raw_rows.append(0)  # filter type: None
        row_start = row * width * channels
        raw_rows.extend(pixels[row_start:row_start + width * channels])

    compressed = zlib.compress(bytes(raw_rows))

    def make_chunk(chunk_type: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)

    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    png = b"\x89PNG\r\n\x1a\n"
    png += make_chunk(b"IHDR", ihdr_data)
    png += make_chunk(b"IDAT", compressed)
    png += make_chunk(b"IEND", b"")
    return png


# ── Magic detection ───────────────────────────────────────────────────────────

class TestMagicDetection:
    def test_detect_png(self):
        assert _detect_magic(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100) == "PNG image"

    def test_detect_jpeg(self):
        assert _detect_magic(b"\xff\xd8\xff" + b"\x00" * 100) == "JPEG image"

    def test_detect_zip(self):
        assert _detect_magic(b"PK\x03\x04" + b"\x00" * 100) == "ZIP archive"

    def test_detect_elf(self):
        assert _detect_magic(b"\x7fELF" + b"\x00" * 100) == "ELF executable"

    def test_detect_pdf(self):
        assert _detect_magic(b"%PDF" + b"\x00" * 100) == "PDF document"

    def test_detect_gzip(self):
        assert _detect_magic(b"\x1f\x8b" + b"\x00" * 100) == "GZIP"

    def test_detect_unknown(self):
        result = _detect_magic(b"\xAA\xBB\xCC\xDD" + b"\x00" * 100)
        assert result is None

    def test_all_magic_entries_are_bytes(self):
        for magic, desc in MAGIC_DB:
            assert isinstance(magic, bytes)
            assert isinstance(desc, str)


# ── PNG pixel parser ──────────────────────────────────────────────────────────

class TestPngPixels:
    def test_valid_png(self):
        png_data = _make_png_with_lsb(b"test", width=4, height=4)
        pixels = _png_pixels(png_data)
        assert pixels is not None
        assert len(pixels) == 16  # 4x4

    def test_invalid_magic(self):
        result = _png_pixels(b"NOTAPNG" + b"\x00" * 100)
        assert result is None

    def test_empty_data(self):
        result = _png_pixels(b"")
        assert result is None


# ── Module actions ────────────────────────────────────────────────────────────

class TestStegoModule:
    def test_file_sig_png(self, stego, tmp_path):
        png = _make_png_with_lsb(b"hello", width=8, height=8)
        f = tmp_path / "test.png"
        f.write_bytes(png)
        result = stego.run("file-sig", file=str(f))
        assert result.success
        assert "PNG" in " ".join(result.findings)

    def test_file_sig_missing_file(self, stego):
        result = stego.run("file-sig", file="/nonexistent/file.bin")
        assert not result.success

    def test_metadata_basic(self, stego, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)
        result = stego.run("metadata", file=str(f))
        assert result.success
        assert any("PNG" in finding for finding in result.findings)

    def test_strings_extracts_ascii(self, stego, tmp_path):
        f = tmp_path / "test.bin"
        # Embed a flag string in binary garbage
        content = b"\x00\x01\x02" + b"CTF{hidden_flag_here}" + b"\x03\x04"
        f.write_bytes(content)
        result = stego.run("strings", file=str(f), min_length=4)
        assert result.success
        assert any("CTF{hidden_flag_here}" in finding for finding in result.findings)

    def test_strings_flag_candidate(self, stego, tmp_path):
        f = tmp_path / "flag_test.bin"
        f.write_bytes(b"\x00" * 10 + b"picoCTF{test_flag_123}" + b"\x00" * 10)
        result = stego.run("strings", file=str(f), min_length=4)
        assert result.success
        flags = result.data.get("flag_candidates", [])
        assert any("picoCTF" in flag for flag in flags) or \
               any("picoCTF" in f for f in result.findings)

    def test_lsb_extract_png(self, stego, tmp_path):
        message = b"CTF{lsb_test}"
        png_data = _make_png_with_lsb(message, width=50, height=50)
        img_file = tmp_path / "stego.png"
        img_file.write_bytes(png_data)
        result = stego.run("lsb-extract", image=str(img_file), bits=1, channel="R")
        assert result.success
        assert result.data.get("extracted_bytes", 0) > 0

    def test_lsb_missing_file(self, stego):
        result = stego.run("lsb-extract", image="/nonexistent/image.png")
        assert not result.success

    def test_polyglot_detection(self, stego, tmp_path):
        # File that contains multiple embedded magic signatures
        f = tmp_path / "polyglot.bin"
        content = (
            b"\x89PNG\r\n\x1a\n"  # PNG header
            + b"\x00" * 20
            + b"PK\x03\x04"       # ZIP magic
            + b"\x00" * 20
            + b"\x1f\x8b"         # GZIP magic
            + b"\x00" * 20
        )
        f.write_bytes(content)
        result = stego.run("file-sig", file=str(f))
        assert result.success
        # Should find embedded signatures
        assert result.data.get("embedded_signatures") is not None
