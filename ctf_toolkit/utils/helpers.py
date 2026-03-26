"""
Shared utility functions for CTF Toolkit.
"""

import hashlib
import os
import re
import struct
from pathlib import Path
from typing import List, Optional, Tuple


def file_md5(path: str) -> str:
    """Return MD5 hex digest of a file."""
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def file_sha256(path: str) -> str:
    """Return SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def hex_dump(data: bytes, width: int = 16) -> str:
    """Format bytes as a classic hex dump."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<{width * 3}}  |{ascii_part}|")
    return "\n".join(lines)


def find_flag(data: str, patterns: Optional[List[str]] = None) -> List[str]:
    """
    Search for CTF flag patterns in text.
    Default patterns cover common CTF formats.
    """
    if patterns is None:
        patterns = [
            r"[A-Za-z0-9_]{2,10}\{[A-Za-z0-9_\-!@#$%^&*\.]{4,80}\}",
            r"CTF\{[^\}]+\}",
            r"flag\{[^\}]+\}",
            r"FLAG\{[^\}]+\}",
            r"picoCTF\{[^\}]+\}",
            r"HTB\{[^\}]+\}",
            r"THM\{[^\}]+\}",
        ]
    found = []
    for pattern in patterns:
        matches = re.findall(pattern, data, re.IGNORECASE)
        found.extend(matches)
    return list(set(found))


def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    """PKCS#7 padding."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def unpad_pkcs7(data: bytes) -> bytes:
    """Remove PKCS#7 padding."""
    if not data:
        raise ValueError("Empty data")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 16:
        raise ValueError("Invalid padding")
    return data[:-pad_len]


def bits_to_bytes(bits: List[int]) -> bytes:
    """Pack list of bits (MSB first) into bytes."""
    result = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for b in range(8):
            byte = (byte << 1) | bits[i + b]
        result.append(byte)
    return bytes(result)


def bytes_to_bits(data: bytes) -> List[int]:
    """Unpack bytes to list of bits (MSB first)."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def normalize_url(url: str) -> str:
    """Ensure URL has a scheme."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")
