"""
Cryptography Module for CTF Toolkit.

Provides:
  - XOR key brute-force and analysis
  - Caesar / ROT cipher brute-force
  - RSA attack utilities (small exponent, factorization, Wiener)
  - Encoding / decoding utilities
  - Frequency analysis
"""

import base64
import math
import string
import urllib.parse
from collections import Counter
from typing import Dict, List, Optional, Tuple

from rich.console import Console
from rich.table import Table
from rich import box

from ctf_toolkit.core.base_module import BaseModule
from ctf_toolkit.core.plugin_system import module
from ctf_toolkit.core.config import config

console = Console()

# English letter frequency reference (most → least common)
ENGLISH_FREQ = "etaoinshrdlcumwfgypbvkjxqz"


# ──────────────────────────────────────────────────────────────────
# Helper utilities
# ──────────────────────────────────────────────────────────────────

def _load_bytes(file: Optional[str], text: Optional[str], as_hex: bool = False) -> bytes:
    """Load data from file or text argument."""
    if file:
        with open(file, "rb") as f:
            data = f.read()
        if as_hex:
            data = bytes.fromhex(data.decode().strip())
        return data
    if text:
        if as_hex:
            return bytes.fromhex(text.strip())
        return text.encode()
    raise ValueError("Provide --file or --text")


def _ic(text: str) -> float:
    """Index of Coincidence for English-likeness detection."""
    text = text.lower()
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(c for c in text if c.isalpha())
    return sum(v * (v - 1) for v in counts.values()) / (n * (n - 1))


def _chi_squared(text: str) -> float:
    """Chi-squared statistic against expected English letter frequencies."""
    expected = {
        "a": 8.2, "b": 1.5, "c": 2.8, "d": 4.3, "e": 12.7, "f": 2.2,
        "g": 2.0, "h": 6.1, "i": 7.0, "j": 0.2, "k": 0.8, "l": 4.0,
        "m": 2.4, "n": 6.7, "o": 7.5, "p": 1.9, "q": 0.1, "r": 6.0,
        "s": 6.3, "t": 9.1, "u": 2.8, "v": 1.0, "w": 2.4, "x": 0.2,
        "y": 2.0, "z": 0.1,
    }
    n = sum(1 for c in text.lower() if c.isalpha())
    if n == 0:
        return float("inf")
    counts = Counter(c for c in text.lower() if c.isalpha())
    chi = 0.0
    for letter, freq in expected.items():
        observed = counts.get(letter, 0)
        exp_count = freq / 100.0 * n
        chi += ((observed - exp_count) ** 2) / exp_count if exp_count else 0
    return chi


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _is_printable_text(data: bytes, threshold: float = 0.85) -> bool:
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return (printable / len(data)) >= threshold if data else False


def _factor_small(n: int) -> Optional[Tuple[int, int]]:
    """Trial division up to sqrt(n) – suitable for CTF-sized moduli."""
    if n % 2 == 0:
        return 2, n // 2
    i = 3
    while i * i <= n:
        if n % i == 0:
            return i, n // i
        i += 2
    return None


def _modpow(base: int, exp: int, mod: int) -> int:
    return pow(base, exp, mod)


def _modinv(a: int, m: int) -> int:
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"No modular inverse for {a} mod {m}")
    return x % m


def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def _iroot(n: int, k: int) -> Tuple[int, bool]:
    """Integer k-th root of n. Returns (root, exact)."""
    if n < 0:
        return 0, False
    if n == 0:
        return 0, True
    u = n
    s = n + 1
    while u < s:
        s = u
        t = (k - 1) * s + n // pow(s, k - 1)
        u = t // k
    return s, pow(s, k) == n


# ──────────────────────────────────────────────────────────────────
# Wiener's attack implementation
# ──────────────────────────────────────────────────────────────────

def _continued_fraction(n: int, d: int) -> List[int]:
    """Compute continued fraction expansion of n/d."""
    result = []
    while d:
        result.append(n // d)
        n, d = d, n % d
    return result


def _convergents(cf: List[int]) -> List[Tuple[int, int]]:
    """Compute convergents from a continued fraction."""
    convergents = []
    h_prev, h_curr = 1, cf[0]
    k_prev, k_curr = 0, 1
    convergents.append((h_curr, k_curr))
    for a in cf[1:]:
        h_prev, h_curr = h_curr, a * h_curr + h_prev
        k_prev, k_curr = k_curr, a * k_curr + k_prev
        convergents.append((h_curr, k_curr))
    return convergents


def _wiener_attack(e: int, n: int) -> Optional[int]:
    """
    Wiener's attack against RSA when d < n^0.25 / 3.
    Returns private key d if vulnerable, else None.
    """
    cf = _continued_fraction(e, n)
    for k, d in _convergents(cf):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # Check if n = p*q with phi(n) = phi
        # x^2 - (n - phi + 1)x + n = 0
        b = n - phi + 1
        discriminant = b * b - 4 * n
        if discriminant < 0:
            continue
        sqrt_disc = int(math.isqrt(discriminant))
        if sqrt_disc * sqrt_disc == discriminant:
            return d
    return None


# ──────────────────────────────────────────────────────────────────
# Main module
# ──────────────────────────────────────────────────────────────────

@module
class CryptoModule(BaseModule):
    """Cryptography attacks and utilities."""

    MODULE_NAME = "crypto"
    MODULE_DESCRIPTION = "XOR cracking, Caesar brute-force, RSA attacks, encoding utilities"

    def get_actions(self) -> List[str]:
        return [
            "xor-crack",
            "caesar-brute",
            "rsa-attack",
            "encode",
            "freq-analysis",
        ]

    # ── XOR crack ────────────────────────────────────────────────────────
    def xor_crack(
        self,
        file: Optional[str] = None,
        text: Optional[str] = None,
        max_keylen: int = 16,
        hex: bool = False,
        **_,
    ) -> None:
        """Brute-force XOR cipher using Index of Coincidence and chi-squared scoring."""
        try:
            data = _load_bytes(file, text, as_hex=hex)
        except Exception as e:
            self._result.add_error(str(e))
            return

        self.logger.info(f"XOR crack on {len(data)} bytes, max keylen={max_keylen}")
        best_results: List[Tuple[float, int, bytes, str]] = []

        for keylen in range(1, min(max_keylen + 1, len(data) + 1)):
            # Divide ciphertext into keylen columns, find best byte for each
            key = bytearray()
            col_scores = []
            for col in range(keylen):
                column = bytes(data[i] for i in range(col, len(data), keylen))
                best_byte = 0
                best_chi = float("inf")
                for candidate in range(256):
                    decrypted = _xor_bytes(column, bytes([candidate]))
                    try:
                        decoded = decrypted.decode("latin-1")
                    except Exception:
                        continue
                    chi = _chi_squared(decoded)
                    if chi < best_chi:
                        best_chi = chi
                        best_byte = candidate
                key.append(best_byte)
                col_scores.append(best_chi)

            key_bytes = bytes(key)
            plaintext_bytes = _xor_bytes(data, key_bytes)
            try:
                plaintext = plaintext_bytes.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    plaintext = plaintext_bytes.decode("latin-1")
                except Exception:
                    continue

            score = sum(col_scores) / len(col_scores)
            is_printable = _is_printable_text(plaintext_bytes)
            best_results.append((score, keylen, key_bytes, plaintext))

        if not best_results:
            self._result.add_error("Could not find a valid XOR key.")
            return

        # Sort by chi-squared score (lower = better)
        best_results.sort(key=lambda x: x[0])
        top_n = best_results[:5]

        for rank, (score, keylen, key_bytes, plaintext) in enumerate(top_n, 1):
            key_hex = key_bytes.hex()
            key_repr = key_bytes.decode("latin-1").replace("\n", "\\n")
            preview = plaintext[:80].replace("\n", "\\n")
            self._result.add_finding(
                f"[Rank {rank}] Key (len={keylen}): {key_hex} | '{key_repr}'\n"
                f"          Preview: {preview}"
            )
            self._result.set_data(f"key_rank_{rank}", {
                "key_hex": key_hex,
                "key_len": keylen,
                "score": round(score, 4),
                "plaintext": plaintext,
            })

    # ── Caesar brute ────────────────────────────────────────────────────
    def caesar_brute(self, text: str, all: bool = False, **_) -> None:
        """Brute-force Caesar / ROT cipher for all 25 shifts."""
        results = []
        for shift in range(1, 26):
            shifted = []
            for ch in text:
                if ch.isalpha():
                    base = ord("A") if ch.isupper() else ord("a")
                    shifted.append(chr((ord(ch) - base + shift) % 26 + base))
                else:
                    shifted.append(ch)
            candidate = "".join(shifted)
            chi = _chi_squared(candidate)
            results.append((chi, shift, candidate))

        results.sort(key=lambda x: x[0])

        if all:
            for chi, shift, candidate in results:
                self._result.add_finding(f"ROT-{shift:02d}: {candidate}")
        else:
            for chi, shift, candidate in results[:3]:
                self._result.add_finding(f"ROT-{shift} (score={chi:.1f}): {candidate}")

        best = results[0]
        self._result.set_data("best_shift", best[1])
        self._result.set_data("best_plaintext", best[2])

    # ── RSA attacks ──────────────────────────────────────────────────────
    def rsa_attack(
        self,
        n: Optional[int] = None,
        e: Optional[int] = None,
        c: Optional[int] = None,
        attack: str = "small-e",
        **_,
    ) -> None:
        """RSA attack dispatcher: small-e, factor, wiener."""
        if not n or not e:
            self._result.add_error("--n and --e are required for RSA attacks.")
            return

        if attack == "small-e":
            self._rsa_small_e(n, e, c)
        elif attack == "factor":
            self._rsa_factor(n, e, c)
        elif attack == "wiener":
            self._rsa_wiener(n, e, c)
        else:
            self._result.add_error(f"Unknown attack type: {attack}")

    def _rsa_small_e(self, n: int, e: int, c: Optional[int]) -> None:
        """
        Small public exponent attack.
        If e is small and m is small, m^e < n, so m = c^(1/e) exactly.
        """
        self._result.add_finding(f"Attempting small-e attack (e={e})")
        if c is None:
            self._result.add_error("Provide --c (ciphertext) for decryption.")
            return

        root, exact = _iroot(c, e)
        if exact:
            self._result.add_finding(f"SUCCESS: m = {root}")
            try:
                msg = root.to_bytes((root.bit_length() + 7) // 8, "big").decode("utf-8")
                self._result.add_finding(f"Decoded message: {msg}")
            except Exception:
                self._result.add_finding(f"Raw integer: {root}")
            self._result.set_data("plaintext_int", root)
        else:
            self._result.add_finding(
                "Direct e-th root failed (m^e > n). "
                "Try padding oracle or broadcast attack."
            )

    def _rsa_factor(self, n: int, e: int, c: Optional[int]) -> None:
        """Trial division factorization attack (small n)."""
        self._result.add_finding(f"Attempting factorization of n={n}")
        factors = _factor_small(n)
        if factors is None:
            self._result.add_finding(
                "Trial division failed. n may be too large. "
                "Try factordb.com or Pollard's rho."
            )
            return

        p, q = factors
        self._result.add_finding(f"Factored: p={p}, q={q}")
        phi = (p - 1) * (q - 1)
        try:
            d = _modinv(e, phi)
            self._result.add_finding(f"Private key d={d}")
            self._result.set_data("p", p)
            self._result.set_data("q", q)
            self._result.set_data("phi", phi)
            self._result.set_data("d", d)

            if c is not None:
                m = pow(c, d, n)
                self._result.add_finding(f"Decrypted m={m}")
                try:
                    msg = m.to_bytes((m.bit_length() + 7) // 8, "big").decode("utf-8")
                    self._result.add_finding(f"Message: {msg}")
                except Exception:
                    pass
        except ValueError as err:
            self._result.add_error(str(err))

    def _rsa_wiener(self, n: int, e: int, c: Optional[int]) -> None:
        """Wiener's attack (small private key d)."""
        self._result.add_finding("Attempting Wiener's attack (small d)...")
        d = _wiener_attack(e, n)
        if d is None:
            self._result.add_finding("Wiener's attack failed. d may not be small enough.")
            return

        self._result.add_finding(f"Wiener SUCCESS: d = {d}")
        self._result.set_data("d", d)

        if c is not None:
            m = pow(c, d, n)
            self._result.add_finding(f"Decrypted m = {m}")
            try:
                msg = m.to_bytes((m.bit_length() + 7) // 8, "big").decode("utf-8")
                self._result.add_finding(f"Message: {msg}")
            except Exception:
                pass

    # ── Encoding ─────────────────────────────────────────────────────────
    def encode(
        self,
        input: str,
        scheme: str,
        decode: bool = False,
        **_,
    ) -> None:
        """Encode or decode a string using the specified scheme."""
        data = input.encode() if not decode else None

        try:
            if scheme == "base64":
                result = base64.b64decode(input).decode() if decode else base64.b64encode(data).decode()
            elif scheme == "base32":
                result = base64.b32decode(input).decode() if decode else base64.b32encode(data).decode()
            elif scheme == "hex":
                result = bytes.fromhex(input).decode("latin-1") if decode else input.encode().hex()
            elif scheme == "url":
                result = urllib.parse.unquote(input) if decode else urllib.parse.quote(input)
            elif scheme == "rot13":
                result = input.translate(str.maketrans(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
                ))
            else:
                self._result.add_error(f"Unknown scheme: {scheme}")
                return
        except Exception as e:
            self._result.add_error(f"Failed to {'decode' if decode else 'encode'}: {e}")
            return

        op = "Decoded" if decode else "Encoded"
        self._result.add_finding(f"{op} ({scheme}): {result}")
        self._result.set_data("result", result)

    # ── Frequency analysis ───────────────────────────────────────────────
    def freq_analysis(
        self,
        file: Optional[str] = None,
        text: Optional[str] = None,
        **_,
    ) -> None:
        """Letter frequency analysis with English comparison."""
        try:
            if file:
                with open(file) as f:
                    content = f.read()
            elif text:
                content = text
            else:
                self._result.add_error("Provide --file or --text")
                return
        except Exception as e:
            self._result.add_error(str(e))
            return

        letters = [c.lower() for c in content if c.isalpha()]
        if not letters:
            self._result.add_error("No alphabetic characters found.")
            return

        total = len(letters)
        counts = Counter(letters)
        top = config.get("crypto", "freq_analysis_top", default=10)

        table = Table(title="Frequency Analysis", box=box.SIMPLE)
        table.add_column("Letter", style="cyan")
        table.add_column("Count", style="yellow")
        table.add_column("Freq %", style="green")
        table.add_column("EN Rank", style="dim")

        for letter, count in counts.most_common(top):
            freq_pct = count / total * 100
            en_rank = ENGLISH_FREQ.index(letter) + 1 if letter in ENGLISH_FREQ else "?"
            table.add_row(letter.upper(), str(count), f"{freq_pct:.1f}%", str(en_rank))
            self._result.add_finding(f"{letter.upper()}: {count} ({freq_pct:.1f}%) | EN rank: {en_rank}")

        console.print(table)
        ic = _ic(content)
        self._result.add_finding(f"Index of Coincidence: {ic:.5f} (EN≈0.0667, random≈0.0385)")
        self._result.set_data("ic", round(ic, 6))
        self._result.set_data("char_count", total)
