"""
Steganography Module for CTF Toolkit.

Provides:
  - LSB (Least Significant Bit) extraction from images
  - EXIF / metadata extraction from files
  - File signature / magic byte detection
  - Printable string extraction from binary files
"""

import io
import os
import re
import struct
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.table import Table
from rich import box

from ctf_toolkit.core.base_module import BaseModule
from ctf_toolkit.core.plugin_system import module
from ctf_toolkit.core.config import config

console = Console()

# ──────────────────────────────────────────────────────────────────
# Magic bytes database (hex prefix → description)
# ──────────────────────────────────────────────────────────────────

MAGIC_DB: List[Tuple[bytes, str]] = [
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image (87a)"),
    (b"GIF89a", "GIF image (89a)"),
    (b"BM", "BMP image"),
    (b"RIFF", "RIFF (WAV/AVI)"),
    (b"ID3", "MP3 audio (ID3)"),
    (b"\xff\xfb", "MP3 audio"),
    (b"OggS", "OGG audio/video"),
    (b"ftyp", "MP4 / ISO base media"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"PK\x05\x06", "ZIP archive (empty)"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"\x1f\x8b", "GZIP"),
    (b"BZh", "BZIP2"),
    (b"\xfd7zXZ", "XZ"),
    (b"7z\xbc\xaf'\x1c", "7-Zip archive"),
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "Windows PE/EXE"),
    (b"\xca\xfe\xba\xbe", "Java class file / Mach-O FAT"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit"),
    (b"%PDF", "PDF document"),
    (b"{\x22", "JSON (likely)"),
    (b"<?xml", "XML document"),
    (b"<!DOCTYPE html", "HTML document"),
    (b"SQLite format 3", "SQLite database"),
    (b"\x00\x00\x00\x0cftyp", "MP4 video"),
    (b"IHDR", "PNG IHDR chunk"),
    (b"\x30\x82", "DER encoded certificate"),
    (b"-----BEGIN", "PEM encoded data"),
    (b"\x00\x01\x00\x00\x00", "TTF font"),
    (b"wOFF", "Web font (WOFF)"),
    (b"wOF2", "Web font (WOFF2)"),
    (b"#!", "Shell script / shebang"),
    (b"\xff\xfe", "UTF-16 LE BOM"),
    (b"\xfe\xff", "UTF-16 BE BOM"),
    (b"\xef\xbb\xbf", "UTF-8 BOM"),
]


def _detect_magic(data: bytes) -> Optional[str]:
    for magic, description in MAGIC_DB:
        if data[:len(magic)] == magic:
            return description
    # Extra: check 4 bytes offset for RIFF sub-types
    if data[8:12] == b"WAVE":
        return "WAV audio"
    if data[8:12] == b"AVI ":
        return "AVI video"
    return None


def _xor_bytes_stego(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


# ──────────────────────────────────────────────────────────────────
# Pure-Python PNG LSB extractor
# ──────────────────────────────────────────────────────────────────

def _png_pixels(data: bytes) -> Optional[List[Tuple[int, ...]]]:
    """Decompress PNG and return flat list of pixel tuples using zlib."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return None

    # Parse IHDR
    pos = 8
    idat_chunks = []
    width = height = bit_depth = color_type = 0

    while pos < len(data) - 4:
        length = struct.unpack_from(">I", data, pos)[0]
        chunk_type = data[pos + 4:pos + 8]
        chunk_data = data[pos + 8:pos + 8 + length]

        if chunk_type == b"IHDR":
            width, height = struct.unpack_from(">II", chunk_data)
            bit_depth = chunk_data[8]
            color_type = chunk_data[9]
        elif chunk_type == b"IDAT":
            idat_chunks.append(chunk_data)
        elif chunk_type == b"IEND":
            break

        pos += 12 + length

    if not idat_chunks:
        return None

    # Channels: 0=Gray, 2=RGB, 3=Indexed, 4=GrayA, 6=RGBA
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color_type, 3)
    raw = zlib.decompress(b"".join(idat_chunks))

    stride = width * channels + 1  # +1 for filter byte
    pixels = []
    for row in range(height):
        row_start = row * stride + 1  # Skip filter byte
        for col in range(width):
            px_start = row_start + col * channels
            pixel = tuple(raw[px_start:px_start + channels])
            pixels.append(pixel)

    return pixels


def _lsb_extract_png(image_path: str, bits: int, channel: str) -> bytes:
    """Extract LSB-encoded data from PNG file."""
    with open(image_path, "rb") as f:
        data = f.read()

    pixels = _png_pixels(data)
    if pixels is None:
        raise ValueError("Could not parse PNG pixel data.")

    # Determine which channels to extract
    channel_map = {"R": [0], "G": [1], "B": [2], "A": [3], "all": [0, 1, 2]}
    channels_to_use = channel_map.get(channel, [0, 1, 2])

    bit_stream = []
    for pixel in pixels:
        for ch_idx in channels_to_use:
            if ch_idx < len(pixel):
                byte_val = pixel[ch_idx]
                for bit in range(bits - 1, -1, -1):
                    bit_stream.append((byte_val >> bit) & 1)

    # Pack bits into bytes
    result = bytearray()
    for i in range(0, len(bit_stream) - 7, 8):
        byte = 0
        for b in range(8):
            byte = (byte << 1) | bit_stream[i + b]
        result.append(byte)

    return bytes(result)


def _lsb_extract_pillow(image_path: str, bits: int, channel: str) -> bytes:
    """Extract LSB using Pillow (better support for JPEG, BMP, etc.)."""
    from PIL import Image
    img = Image.open(image_path).convert("RGB")
    pixels = list(img.getdata())

    channel_map = {"R": [0], "G": [1], "B": [2], "A": [3], "all": [0, 1, 2]}
    channels_to_use = channel_map.get(channel, [0, 1, 2])

    bit_stream = []
    for pixel in pixels:
        for ch_idx in channels_to_use:
            if ch_idx < len(pixel):
                byte_val = pixel[ch_idx]
                for bit in range(bits - 1, -1, -1):
                    bit_stream.append((byte_val >> bit) & 1)

    result = bytearray()
    for i in range(0, len(bit_stream) - 7, 8):
        byte = 0
        for b in range(8):
            byte = (byte << 1) | bit_stream[i + b]
        result.append(byte)

    return bytes(result)


# ──────────────────────────────────────────────────────────────────
# Metadata extraction
# ──────────────────────────────────────────────────────────────────

def _extract_exif_basic(data: bytes) -> Dict[str, Any]:
    """Basic EXIF extraction for JPEG without exiftool."""
    result = {}
    if data[:2] != b"\xff\xd8":
        return result

    pos = 2
    while pos < len(data) - 2:
        if data[pos] != 0xff:
            break
        marker = data[pos + 1]
        if marker == 0xe1:  # APP1 - EXIF
            length = struct.unpack_from(">H", data, pos + 2)[0]
            app1_data = data[pos + 4:pos + 2 + length]
            if app1_data[:4] == b"Exif":
                result["has_exif"] = True
                # Extract some printable strings
                strings = re.findall(rb"[ -~]{4,}", app1_data)
                result["exif_strings"] = [s.decode("ascii", errors="ignore") for s in strings[:20]]
            break
        length = struct.unpack_from(">H", data, pos + 2)[0]
        pos += 2 + length

    return result


def _run_exiftool(path: str) -> Dict[str, str]:
    """Run exiftool if available."""
    import subprocess
    try:
        result = subprocess.run(
            ["exiftool", path],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0:
            return {}
        meta = {}
        for line in result.stdout.splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                meta[key.strip()] = value.strip()
        return meta
    except FileNotFoundError:
        return {}


# ──────────────────────────────────────────────────────────────────
# Main module
# ──────────────────────────────────────────────────────────────────

@module
class StegoModule(BaseModule):
    """Steganography analysis and extraction tools."""

    MODULE_NAME = "stego"
    MODULE_DESCRIPTION = "LSB extraction, metadata analysis, file signatures, string extraction"

    def get_actions(self) -> List[str]:
        return ["lsb-extract", "metadata", "file-sig", "strings"]

    # ── LSB extraction ────────────────────────────────────────────────────
    def lsb_extract(
        self,
        image: str,
        bits: int = 1,
        channel: str = "all",
        **_,
    ) -> None:
        """Extract LSB-encoded data from an image."""
        path = Path(image)
        if not path.exists():
            self._result.add_error(f"Image not found: {image}")
            return

        self.logger.info(f"LSB extraction: {path.name}, bits={bits}, channel={channel}")

        # Try pure-Python PNG first, then Pillow
        raw_data = None
        try:
            if path.suffix.lower() == ".png":
                raw_data = _lsb_extract_png(image, bits, channel)
            else:
                raw_data = _lsb_extract_pillow(image, bits, channel)
        except ImportError:
            # Pillow not installed – try pure PNG
            try:
                raw_data = _lsb_extract_png(image, bits, channel)
            except Exception as e:
                self._result.add_error(f"LSB extraction failed: {e}. Install Pillow: pip install Pillow")
                return
        except Exception as e:
            self._result.add_error(f"LSB extraction error: {e}")
            return

        if raw_data is None:
            self._result.add_error("No data extracted.")
            return

        # Check magic bytes
        sig = _detect_magic(raw_data)
        if sig:
            self._result.add_finding(f"Embedded file detected: {sig}")

        # Try to interpret as text
        printable = bytearray()
        for b in raw_data:
            if 32 <= b < 127 or b in (9, 10, 13):
                printable.append(b)
            else:
                if len(printable) >= 4:
                    break
                printable = bytearray()

        preview_text = printable[:200].decode("ascii", errors="replace")
        if len(printable) >= 4:
            self._result.add_finding(f"Text preview: {preview_text}")

        # Look for flag patterns
        flag_match = re.search(
            rb"[A-Za-z0-9_]{2,10}\{[A-Za-z0-9_\-!@#$%^&*]{4,80}\}",
            raw_data,
        )
        if flag_match:
            self._result.add_finding(f"FLAG CANDIDATE: {flag_match.group().decode('ascii', errors='replace')}")

        # Save extracted data
        out_file = self.output_dir / f"lsb_{path.stem}_extracted.bin"
        out_file.write_bytes(raw_data)
        self._result.add_finding(f"Extracted {len(raw_data)} bytes → {out_file}")
        self._result.set_data("extracted_bytes", len(raw_data))
        self._result.set_data("output_file", str(out_file))
        if sig:
            self._result.set_data("detected_type", sig)

    # ── Metadata extraction ───────────────────────────────────────────────
    def metadata(self, file: str, **_) -> None:
        """Extract metadata from a file using exiftool and basic parsing."""
        path = Path(file)
        if not path.exists():
            self._result.add_error(f"File not found: {file}")
            return

        with open(path, "rb") as f:
            raw = f.read()

        # Basic file info
        stat = path.stat()
        self._result.add_finding(f"File: {path.name}")
        self._result.add_finding(f"Size: {stat.st_size} bytes")

        sig = _detect_magic(raw)
        if sig:
            self._result.add_finding(f"Type: {sig}")

        # Try exiftool first
        exif = _run_exiftool(file)
        if exif:
            self._result.add_finding(f"Metadata ({len(exif)} fields via exiftool):")
            for key, value in list(exif.items())[:30]:
                self._result.add_finding(f"  {key}: {value}")
            self._result.set_data("exif", exif)
        else:
            # Fallback: basic JPEG EXIF
            basic = _extract_exif_basic(raw)
            if basic.get("has_exif"):
                self._result.add_finding("EXIF data present (install exiftool for full parse).")
                for s in basic.get("exif_strings", [])[:10]:
                    if len(s) > 3:
                        self._result.add_finding(f"  EXIF string: {s}")
            else:
                self._result.add_finding("No EXIF data found. Install exiftool for full metadata.")

        # Look for strings of interest in raw bytes
        for pattern in [rb"GPS", rb"Author", rb"Creator", rb"Comment", rb"Description"]:
            idx = raw.find(pattern)
            if idx != -1:
                snippet = raw[idx:idx + 64].decode("latin-1", errors="replace")
                self._result.add_finding(f"Found: {snippet.strip()}")

    # ── File signature ────────────────────────────────────────────────────
    def file_sig(self, file: str, **_) -> None:
        """Detect file type from magic bytes and scan for embedded signatures."""
        path = Path(file)
        if not path.exists():
            self._result.add_error(f"File not found: {file}")
            return

        with open(path, "rb") as f:
            raw = f.read()

        # Primary signature
        sig = _detect_magic(raw)
        self._result.add_finding(f"Primary signature: {sig or 'Unknown'}")
        self._result.add_finding(f"Magic bytes: {raw[:8].hex()}")

        # Scan for embedded signatures
        embedded = []
        for magic, desc in MAGIC_DB:
            # Skip the first occurrence (already reported)
            pos = 0
            while True:
                idx = raw.find(magic, pos + 1)
                if idx == -1:
                    break
                embedded.append((idx, desc))
                pos = idx

        # Sort by offset
        embedded.sort()
        if embedded:
            self._result.add_finding(f"Embedded signatures ({len(embedded)}):")
            for offset, desc in embedded[:15]:
                self._result.add_finding(f"  @ 0x{offset:08x} ({offset}): {desc}")

        self._result.set_data("primary_type", sig)
        self._result.set_data("embedded_signatures", [(o, d) for o, d in embedded[:20]])

        # Polyglot detection
        if len(set(d for _, d in embedded)) > 2:
            self._result.add_finding(
                "⚠ Multiple file types detected – possible polyglot or steganographic container!"
            )

    # ── String extraction ─────────────────────────────────────────────────
    def strings(self, file: str, min_length: int = 4, **_) -> None:
        """Extract printable ASCII and Unicode strings from a file."""
        path = Path(file)
        if not path.exists():
            self._result.add_error(f"File not found: {file}")
            return

        with open(path, "rb") as f:
            raw = f.read()

        # ASCII strings
        ascii_strings = re.findall(
            rb"[ -~]{" + str(min_length).encode() + rb",}",
            raw,
        )
        ascii_decoded = [s.decode("ascii", errors="replace") for s in ascii_strings]

        # Unicode (UTF-16 LE) strings
        unicode_strings = re.findall(
            rb"(?:[\x20-\x7e]\x00){" + str(min_length).encode() + rb",}",
            raw,
        )
        unicode_decoded = [
            s.decode("utf-16-le", errors="replace") for s in unicode_strings
        ]

        all_strings = ascii_decoded + unicode_decoded

        # Flag candidates
        flag_re = re.compile(r"[A-Za-z0-9_]{2,10}\{[A-Za-z0-9_\-!@#$%^&*]{4,80}\}")
        flags = [s for s in all_strings if flag_re.search(s)]

        if flags:
            for f in flags:
                self._result.add_finding(f"🚩 FLAG CANDIDATE: {f}")
        else:
            self._result.add_finding("No flag-format strings found.")

        # Interesting strings
        interest_patterns = [
            r"https?://\S+",
            r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
            r"password|passwd|secret|key|token|api",
            r"/[a-z/]+\.(php|html|py|sh|txt|conf)",
        ]
        interesting = []
        for s in all_strings:
            for pat in interest_patterns:
                if re.search(pat, s, re.IGNORECASE):
                    interesting.append(s)
                    break

        if interesting:
            self._result.add_finding(f"Interesting strings ({len(interesting)}):")
            for s in interesting[:20]:
                self._result.add_finding(f"  {s}")

        self._result.add_finding(
            f"Total strings: {len(ascii_decoded)} ASCII, {len(unicode_decoded)} Unicode"
        )

        # Save all strings to file
        out_file = self.output_dir / f"strings_{path.stem}.txt"
        out_file.write_text("\n".join(all_strings))
        self._result.add_finding(f"All strings saved to: {out_file}")
        self._result.set_data("string_count", len(all_strings))
        self._result.set_data("flag_candidates", flags)
