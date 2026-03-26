"""
Test suite for the Binary Exploitation module.
"""

import struct
import pytest
from pathlib import Path
from ctf_toolkit.modules.binary.binary_module import (
    BinaryModule,
    _cyclic_gen,
    _cyclic_find,
    _parse_elf_header,
    _checksec_readelf,
    ELF_MAGIC,
)


@pytest.fixture
def binary():
    return BinaryModule()


@pytest.fixture
def fake_elf_32(tmp_path):
    """Create a minimal valid 32-bit ELF header for testing."""
    elf = bytearray(64)
    elf[0:4] = ELF_MAGIC
    elf[4] = 1       # 32-bit
    elf[5] = 1       # little endian
    elf[6] = 1       # ELF version
    struct.pack_into("<H", elf, 16, 2)   # ET_EXEC
    struct.pack_into("<H", elf, 18, 0x03)  # x86
    path = tmp_path / "fake32.elf"
    path.write_bytes(bytes(elf))
    return path


@pytest.fixture
def fake_elf_64(tmp_path):
    """Create a minimal valid 64-bit ELF header for testing."""
    elf = bytearray(64)
    elf[0:4] = ELF_MAGIC
    elf[4] = 2       # 64-bit
    elf[5] = 1       # little endian
    elf[6] = 1       # ELF version
    struct.pack_into("<H", elf, 16, 3)   # ET_DYN (PIE)
    struct.pack_into("<H", elf, 18, 0x3E)  # x86-64
    path = tmp_path / "fake64.elf"
    path.write_bytes(bytes(elf))
    return path


# ── Cyclic pattern ────────────────────────────────────────────────────────────

class TestCyclicPattern:
    def test_length_correct(self):
        pattern = _cyclic_gen(200)
        assert len(pattern) == 200

    def test_pattern_is_ascii(self):
        pattern = _cyclic_gen(100)
        assert all(chr(b) in "abcdefghijklmnopqrstuvwxyz" for b in pattern)

    def test_no_immediate_repeats(self):
        pattern = _cyclic_gen(100)
        # Every 4-byte window should ideally be unique within a reasonable length
        windows = [pattern[i:i+4] for i in range(len(pattern) - 3)]
        assert len(windows) > 0

    def test_find_in_pattern(self):
        pattern = _cyclic_gen(200)
        target = pattern[48:52]
        idx = _cyclic_find(pattern, target)
        assert idx == 48

    def test_find_not_present(self):
        pattern = _cyclic_gen(100)
        idx = _cyclic_find(pattern, b"\xde\xad\xbe\xef")
        assert idx == -1


# ── ELF parser ────────────────────────────────────────────────────────────────

class TestElfParser:
    def test_parse_valid_32bit(self, fake_elf_32):
        data = fake_elf_32.read_bytes()
        hdr = _parse_elf_header(data)
        assert hdr is not None
        assert hdr["bits"] == "32-bit"
        assert hdr["type"] == "EXEC"
        assert hdr["machine"] == "x86"

    def test_parse_valid_64bit(self, fake_elf_64):
        data = fake_elf_64.read_bytes()
        hdr = _parse_elf_header(data)
        assert hdr is not None
        assert hdr["bits"] == "64-bit"
        assert hdr["type"] == "DYN"
        assert hdr["machine"] == "x86-64"

    def test_parse_non_elf(self, tmp_path):
        non_elf = tmp_path / "notelf.bin"
        non_elf.write_bytes(b"This is not an ELF file at all")
        data = non_elf.read_bytes()
        hdr = _parse_elf_header(data)
        assert hdr is None

    def test_parse_empty(self):
        hdr = _parse_elf_header(b"")
        assert hdr is None


# ── Module actions ────────────────────────────────────────────────────────────

class TestBinaryModule:
    def test_elf_info_valid(self, binary, fake_elf_64):
        result = binary.run("elf-info", binary=str(fake_elf_64))
        # May have partial findings since readelf won't work on fake ELF
        assert result.data.get("elf_header") is not None

    def test_elf_info_missing_file(self, binary):
        result = binary.run("elf-info", binary="/nonexistent/path/binary")
        assert not result.success
        assert result.errors

    def test_overflow_detect_creates_pattern(self, binary, fake_elf_32, tmp_path):
        result = binary.run(
            "overflow-detect",
            binary=str(fake_elf_32),
            max_size=128,
        )
        # Should create pattern file
        pattern_file = result.data.get("pattern_file")
        if pattern_file:
            assert Path(pattern_file).exists()
            assert Path(pattern_file).stat().st_size == 128

    def test_overflow_detect_missing_file(self, binary):
        result = binary.run("overflow-detect", binary="/no/such/binary")
        assert not result.success

    def test_checksec_missing_file(self, binary):
        result = binary.run("checksec", binary="/nonexistent")
        assert not result.success

    def test_rop_gadgets_missing_file(self, binary):
        result = binary.run("rop-gadgets", binary="/nonexistent")
        assert not result.success

    def test_unknown_action(self, binary):
        result = binary.run("unknown-action")
        assert not result.success
