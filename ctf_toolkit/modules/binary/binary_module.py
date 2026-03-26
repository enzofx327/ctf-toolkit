"""
Binary Exploitation Module for CTF Toolkit.

Provides:
  - ELF binary analysis (sections, imports, symbols)
  - Security flags check (NX, PIE, RELRO, canary, ASLR)
  - Buffer overflow pattern generation and offset detection
  - ROP gadget search helper
"""

import os
import re
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console
from rich.table import Table
from rich import box

from ctf_toolkit.core.base_module import BaseModule
from ctf_toolkit.core.plugin_system import module

console = Console()


def _require_binary(path: str) -> Optional[Path]:
    """Validate binary path and return Path or None."""
    p = Path(path)
    if not p.exists():
        return None
    if not p.is_file():
        return None
    return p


def _run(cmd: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a command safely and return result."""
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


# ──────────────────────────────────────────────────────────────────
# Cyclic pattern helpers (De Bruijn sequence)
# ──────────────────────────────────────────────────────────────────

def _cyclic_gen(length: int, n: int = 4) -> bytes:
    """Generate a De Bruijn cyclic pattern of given length."""
    alphabet = b"abcdefghijklmnopqrstuvwxyz"
    k = len(alphabet)
    pattern = bytearray()

    # Simple De Bruijn via shift register
    a = [0] * k * n
    sequence = []

    def db(t: int, p: int) -> None:
        if t > n:
            if n % p == 0:
                sequence.extend(a[1 : p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    for i in sequence:
        pattern.append(alphabet[i])
        if len(pattern) >= length:
            break

    return bytes(pattern[:length])


def _cyclic_find(pattern: bytes, value: bytes) -> int:
    """Find offset of a 4-byte value within a cyclic pattern."""
    idx = pattern.find(value)
    return idx


# ──────────────────────────────────────────────────────────────────
# ELF parser (pure Python, no pwntools dependency at import)
# ──────────────────────────────────────────────────────────────────

ELF_MAGIC = b"\x7fELF"

EI_CLASS = {1: "32-bit", 2: "64-bit"}
EI_DATA = {1: "Little Endian", 2: "Big Endian"}
EI_TYPE = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
EI_MACHINE = {
    0x03: "x86", 0x3E: "x86-64",
    0x28: "ARM", 0xB7: "AArch64",
    0x08: "MIPS",
}


def _parse_elf_header(data: bytes) -> Optional[Dict]:
    if data[:4] != ELF_MAGIC:
        return None
    bits = EI_CLASS.get(data[4], "Unknown")
    endian = EI_DATA.get(data[5], "Unknown")
    etype = EI_TYPE.get(struct.unpack_from("<H", data, 16)[0], "Unknown")
    machine = EI_MACHINE.get(struct.unpack_from("<H", data, 18)[0], hex(data[18]))
    return {
        "bits": bits,
        "endian": endian,
        "type": etype,
        "machine": machine,
    }


# ──────────────────────────────────────────────────────────────────
# checksec logic (reads ELF sections/flags directly)
# ──────────────────────────────────────────────────────────────────

def _checksec_readelf(path: str) -> Dict[str, str]:
    """Parse checksec-style flags using readelf."""
    flags: Dict[str, str] = {
        "NX": "unknown",
        "PIE": "unknown",
        "RELRO": "none",
        "Canary": "unknown",
        "RPATH": "none",
    }

    # PIE: check e_type = ET_DYN
    try:
        with open(path, "rb") as f:
            hdr = _parse_elf_header(f.read(64))
        if hdr:
            flags["PIE"] = "enabled" if hdr["type"] == "DYN" else "disabled"
    except Exception:
        pass

    # NX: check GNU_STACK segment
    result = _run(["readelf", "-l", path])
    if result.returncode == 0:
        if "GNU_STACK" in result.stdout:
            for line in result.stdout.splitlines():
                if "GNU_STACK" in line:
                    flags["NX"] = "disabled" if "RWE" in line or "0x7" in line else "enabled"
                    break

    # RELRO
    result = _run(["readelf", "-d", path])
    if result.returncode == 0:
        if "BIND_NOW" in result.stdout:
            flags["RELRO"] = "full"
        elif "GNU_RELRO" in result.stdout:
            flags["RELRO"] = "partial"

    # Canary: check for __stack_chk_fail in symbols
    result = _run(["readelf", "--syms", path])
    if result.returncode == 0:
        flags["Canary"] = "found" if "__stack_chk_fail" in result.stdout else "not found"

    # RPATH
    result = _run(["readelf", "-d", path])
    if result.returncode == 0:
        if "RPATH" in result.stdout or "RUNPATH" in result.stdout:
            flags["RPATH"] = "set (potential issue)"

    return flags


# ──────────────────────────────────────────────────────────────────
# ROP gadget search (via ROPgadget or objdump fallback)
# ──────────────────────────────────────────────────────────────────

GADGET_PATTERNS = {
    "ret": re.compile(r"ret\b", re.IGNORECASE),
    "pop": re.compile(r"pop\s+[a-z]{2,3}", re.IGNORECASE),
    "syscall": re.compile(r"(syscall|int\s+0x80)", re.IGNORECASE),
    "jmp": re.compile(r"jmp\s+[a-z]{2,3}", re.IGNORECASE),
}


def _rop_via_ropgadget(binary: str, gtype: str) -> List[str]:
    """Try ROPgadget tool first."""
    try:
        result = _run(["ROPgadget", "--binary", binary, "--rop"])
        if result.returncode != 0:
            return []
        gadgets = []
        pattern = GADGET_PATTERNS.get(gtype)
        for line in result.stdout.splitlines():
            if " : " not in line:
                continue
            if gtype == "all" or (pattern and pattern.search(line)):
                gadgets.append(line.strip())
        return gadgets
    except FileNotFoundError:
        return []


def _rop_via_objdump(binary: str, gtype: str) -> List[str]:
    """Fallback: objdump disassembly + regex search."""
    try:
        result = _run(["objdump", "-d", "-M", "intel", binary])
        if result.returncode != 0:
            return []
        gadgets = []
        pattern = GADGET_PATTERNS.get(gtype)
        for line in result.stdout.splitlines():
            addr_match = re.match(r"\s*([0-9a-f]+):\s+(.+)", line)
            if not addr_match:
                continue
            addr, instr = addr_match.groups()
            if gtype == "all" or (pattern and pattern.search(instr)):
                gadgets.append(f"0x{addr}: {instr.strip()}")
        return gadgets[:200]  # Cap at 200 for display
    except FileNotFoundError:
        return []


# ──────────────────────────────────────────────────────────────────
# Main module
# ──────────────────────────────────────────────────────────────────

@module
class BinaryModule(BaseModule):
    """Binary exploitation utilities."""

    MODULE_NAME = "binary"
    MODULE_DESCRIPTION = "ELF analysis, overflow detection, ROP gadgets, checksec"

    def get_actions(self) -> List[str]:
        return ["elf-info", "checksec", "overflow-detect", "rop-gadgets"]

    # ── ELF info ─────────────────────────────────────────────────────────
    def elf_info(self, binary: str, **_) -> None:
        """Parse and display ELF binary structure."""
        path = _require_binary(binary)
        if not path:
            self._result.add_error(f"Binary not found or not a file: {binary}")
            return

        with open(path, "rb") as f:
            data = f.read()

        hdr = _parse_elf_header(data)
        if not hdr:
            self._result.add_error(f"Not a valid ELF file: {binary}")
            return

        size = path.stat().st_size
        self._result.add_finding(f"File:      {path.name} ({size} bytes)")
        self._result.add_finding(f"Arch:      {hdr['machine']} ({hdr['bits']}, {hdr['endian']})")
        self._result.add_finding(f"Type:      {hdr['type']}")

        # Sections via readelf
        result = _run(["readelf", "-S", binary])
        if result.returncode == 0:
            sections = []
            for line in result.stdout.splitlines():
                m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)", line)
                if m:
                    name, stype, addr, offset = m.groups()
                    sections.append(f"{name} ({stype}) @ 0x{addr}")

            self._result.add_finding(f"Sections ({len(sections)}): {', '.join(sections[:10])}")
            self._result.set_data("sections", sections)

        # Dynamic imports
        result = _run(["readelf", "-d", binary])
        if result.returncode == 0:
            needed = [
                line.split("[")[1].rstrip("]")
                for line in result.stdout.splitlines()
                if "(NEEDED)" in line
            ]
            self._result.add_finding(f"Libraries: {', '.join(needed) or 'none'}")
            self._result.set_data("libraries", needed)

        # Strings of interest (flags, passwords)
        interesting = []
        for s in re.findall(rb"[ -~]{6,}", data):
            decoded = s.decode("ascii", errors="ignore")
            if any(kw in decoded.lower() for kw in ["flag", "ctf", "pass", "secret", "key", "http"]):
                interesting.append(decoded)

        if interesting:
            self._result.add_finding(f"Interesting strings: {'; '.join(interesting[:8])}")
            self._result.set_data("interesting_strings", interesting[:20])

        self._result.set_data("elf_header", hdr)

    # ── checksec ─────────────────────────────────────────────────────────
    def checksec(self, binary: str, **_) -> None:
        """Check binary security mitigations."""
        path = _require_binary(binary)
        if not path:
            self._result.add_error(f"Binary not found: {binary}")
            return

        # Prefer system checksec if available
        result = _run(["checksec", "--file", binary])
        if result.returncode == 0 and "NX" in result.stdout + result.stderr:
            for line in (result.stdout + result.stderr).splitlines():
                if any(kw in line for kw in ["NX", "PIE", "RELRO", "Canary", "Stack"]):
                    self._result.add_finding(line.strip())
            return

        # Fallback: manual readelf
        flags = _checksec_readelf(binary)
        table = Table(title="Security Flags", box=box.SIMPLE)
        table.add_column("Feature", style="cyan")
        table.add_column("Status")
        colors = {"enabled": "green", "full": "green", "found": "green",
                  "disabled": "red", "none": "red", "not found": "red",
                  "partial": "yellow", "unknown": "dim"}
        for feature, status in flags.items():
            color = colors.get(status, "white")
            table.add_row(feature, f"[{color}]{status}[/{color}]")
            self._result.add_finding(f"{feature}: {status}")
        console.print(table)
        self._result.set_data("checksec", flags)

    # ── Overflow detection ────────────────────────────────────────────────
    def overflow_detect(self, binary: str, max_size: int = 512, **_) -> None:
        """
        Generate cyclic patterns and guide manual overflow offset detection.
        Also reports function call sites and dangerous libc calls.
        """
        path = _require_binary(binary)
        if not path:
            self._result.add_error(f"Binary not found: {binary}")
            return

        # Generate patterns
        pattern = _cyclic_gen(max_size)
        pattern_hex = pattern[:32].hex()

        self._result.add_finding(f"Generated De Bruijn pattern (len={max_size})")
        self._result.add_finding(f"Pattern preview: {pattern[:64].decode('ascii')}")

        # Save full pattern
        pattern_file = self.output_dir / f"pattern_{path.stem}.txt"
        pattern_file.write_bytes(pattern)
        self._result.add_finding(f"Full pattern saved to: {pattern_file}")

        # Scan for dangerous functions
        dangerous = ["gets", "strcpy", "strcat", "sprintf", "scanf", "read",
                     "memcpy", "fgets", "snprintf"]
        result = _run(["objdump", "-d", binary])
        found_dangerous = []
        if result.returncode == 0:
            for func in dangerous:
                if func in result.stdout:
                    # Find approximate call addresses
                    addrs = re.findall(rf"([0-9a-f]+)\s+<{re.escape(func)}@plt>", result.stdout)
                    found_dangerous.append(
                        f"{func}{'@' + addrs[0] if addrs else ''}"
                    )

        if found_dangerous:
            self._result.add_finding(
                f"Potentially dangerous calls: {', '.join(found_dangerous)}"
            )
        else:
            self._result.add_finding("No obvious dangerous function calls detected.")

        # pwntools usage hint
        self._result.add_finding(
            "Next steps:\n"
            "  1. Run binary with pattern as input:\n"
            f"     echo '{pattern[:64].decode()}...' | ./{path.name}\n"
            "  2. Check crash EIP/RIP value in GDB\n"
            "  3. Find offset: python3 -c \"from pwn import *; print(cyclic_find(0xDEADBEEF))\""
        )

        self._result.set_data("pattern_file", str(pattern_file))
        self._result.set_data("dangerous_functions", found_dangerous)
        self._result.set_data("pwntools_snippet", (
            f"from pwn import *\n"
            f"elf = ELF('{binary}')\n"
            f"p = process('{binary}')\n"
            f"padding = cyclic(200)\n"
            f"p.sendline(padding)\n"
            f"p.wait()\n"
            f"# offset = cyclic_find(core.read(rsp_or_eip_value, 4))\n"
        ))

    # ── ROP gadgets ───────────────────────────────────────────────────────
    def rop_gadgets(self, binary: str, type: str = "all", **_) -> None:
        """Search for ROP gadgets in a binary."""
        path = _require_binary(binary)
        if not path:
            self._result.add_error(f"Binary not found: {binary}")
            return

        self.logger.info(f"Searching for ROP gadgets (type={type}) in {path.name}")

        gadgets = _rop_via_ropgadget(binary, type)
        if not gadgets:
            self.logger.info("ROPgadget not available, falling back to objdump...")
            gadgets = _rop_via_objdump(binary, type)

        if not gadgets:
            self._result.add_finding(
                "No gadgets found. Install ROPgadget: pip install ropgadget"
            )
            return

        self._result.add_finding(f"Found {len(gadgets)} gadget(s) (type={type})")

        # Show sample
        for g in gadgets[:20]:
            self._result.add_finding(g)

        if len(gadgets) > 20:
            self._result.add_finding(f"... and {len(gadgets) - 20} more. See saved output.")

        self._result.set_data("gadget_count", len(gadgets))
        self._result.set_data("gadgets", gadgets[:100])
