# CTF Toolkit

A production-grade, modular framework for Capture The Flag competitions — built for real-world use, not demos.

```
  ██████╗████████╗███████╗    ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
 ██╔════╝╚══██╔══╝██╔════╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
 ██║        ██║   █████╗         ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║
 ██║        ██║   ██╔══╝         ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║
 ╚██████╗   ██║   ██║            ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║
  ╚═════╝   ╚═╝   ╚═╝            ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝
```

**v1.0.0** · Binary · Crypto · Stego · Web

---

## Features

| Module      | Capabilities |
|-------------|-------------|
| **Binary**  | ELF analysis, checksec flags, De Bruijn overflow patterns, ROP gadget search |
| **Crypto**  | XOR key brute-force (IC + chi-squared), Caesar/ROT brute-force, RSA attacks (small-e, factorization, Wiener), encoding/decoding, frequency analysis |
| **Stego**   | LSB extraction (PNG/JPEG/BMP), metadata extraction (exiftool), file magic detection, polyglot detection, string extraction |
| **Web**     | Target reconnaissance, SQL injection detection (error/time/boolean-based), threaded directory brute-force, XSS reflection detection, custom HTTP requests |

**Architecture highlights:**
- Plugin system: drop a `.py` file in `plugins_external/` — it auto-loads on startup
- All results saved to `output/` as timestamped JSON
- Coloured rich output with progress indicators
- YAML + `.env` configuration with environment overrides
- Full test suite with `pytest`

---

## Requirements

- Python 3.9+
- Linux recommended for binary exploitation (pwntools requirement)
- Optional system tools: `readelf`, `objdump`, `ROPgadget`, `exiftool`, `checksec`

---

## Installation

### 1. Clone and set up

```bash
git clone <repo-url> ctf-toolkit
cd ctf-toolkit
```

### 2. Create virtual environment (recommended)

```bash
python3 -m venv venv
source venv/bin/activate       # Linux/macOS
# venv\Scripts\activate.bat    # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Install as CLI tool (optional but recommended)

```bash
pip install -e .
```

After this, `toolkit` is available system-wide:

```bash
toolkit --version
toolkit --list
```

### 5. (Optional) Install pwntools for full binary exploitation support

```bash
pip install pwntools
```

### 6. Configure (optional)

```bash
cp .env.example .env
# Edit .env or config.yaml as needed
```

---

## Quick Start

```bash
# List all modules and actions
toolkit --list

# Crypto: brute-force XOR cipher
toolkit crypto xor-crack --file encrypted.bin

# Crypto: RSA small-exponent attack
toolkit crypto rsa-attack --n 3233 --e 3 --c 125 --attack small-e

# Crypto: Caesar brute-force
toolkit crypto caesar-brute --text "Khoor Zruog"

# Crypto: Base64 decode
toolkit crypto encode --input "Q1RGe3Rlc3R9" --scheme base64 --decode

# Binary: Analyze ELF binary
toolkit binary elf-info --binary ./vuln

# Binary: Check security mitigations
toolkit binary checksec --binary ./challenge

# Binary: Generate overflow pattern
toolkit binary overflow-detect --binary ./vuln --max-size 256

# Binary: Find ROP gadgets
toolkit binary rop-gadgets --binary ./challenge --type pop

# Stego: Extract LSB data from image
toolkit stego lsb-extract --image flag.png --bits 1 --channel all

# Stego: Detect file magic signatures
toolkit stego file-sig --file suspicious.bin

# Stego: Extract metadata
toolkit stego metadata --file image.jpg

# Stego: Extract strings and flag candidates
toolkit stego strings --file challenge.bin --min-length 6

# Web: Full target scan
toolkit web scan --url http://target.ctf.local

# Web: SQL injection probe
toolkit web sqli --url "http://target.ctf.local/page?id=1"

# Web: Directory brute-force
toolkit web dir-brute --url http://target.ctf.local --threads 20

# Web: XSS detection
toolkit web xss --url "http://target.ctf.local/search?q=test"

# Web: Custom request
toolkit web request --url http://target.ctf.local/api --method POST --data "user=admin&pass=test"
```

---

## Command Reference

### Global Flags

```
--version           Print version
--list              List all modules and actions
--log-level LEVEL   Override log level (DEBUG|INFO|WARNING|ERROR)
--output-dir DIR    Override output directory
--save              Force save results to output directory
--no-color          Disable colored output
```

### `crypto` module

| Action | Required | Optional | Description |
|--------|----------|----------|-------------|
| `xor-crack` | `--file` or `--text` | `--max-keylen`, `--hex` | XOR key brute-force |
| `caesar-brute` | `--text` | `--all` | All 25 ROT shifts |
| `rsa-attack` | `--n`, `--e` | `--c`, `--attack` | RSA attacks |
| `encode` | `--input`, `--scheme` | `--decode` | Encode/decode |
| `freq-analysis` | `--file` or `--text` | — | Letter frequency + IC |

**RSA attack types:** `small-e` (default) · `factor` · `wiener`  
**Encoding schemes:** `base64` · `base32` · `hex` · `url` · `rot13`

---

### `binary` module

| Action | Required | Optional | Description |
|--------|----------|----------|-------------|
| `elf-info` | `--binary` | — | Sections, imports, interesting strings |
| `checksec` | `--binary` | — | NX, PIE, RELRO, canary |
| `overflow-detect` | `--binary` | `--max-size` | De Bruijn pattern + dangerous call scan |
| `rop-gadgets` | `--binary` | `--type` | Gadget search via ROPgadget/objdump |

**ROP gadget types:** `all` (default) · `ret` · `pop` · `syscall`

---

### `stego` module

| Action | Required | Optional | Description |
|--------|----------|----------|-------------|
| `lsb-extract` | `--image` | `--bits`, `--channel` | LSB steganography extraction |
| `metadata` | `--file` | — | EXIF + file metadata |
| `file-sig` | `--file` | — | Magic byte detection + embedded sigs |
| `strings` | `--file` | `--min-length` | ASCII/Unicode string extraction |

**Channels:** `R` · `G` · `B` · `A` · `all` (default)

---

### `web` module

| Action | Required | Optional | Description |
|--------|----------|----------|-------------|
| `scan` | `--url` | `--headers` | Recon: headers, tech, common paths |
| `sqli` | `--url` | `--param`, `--method` | Error/time/boolean SQLi detection |
| `dir-brute` | `--url` | `--wordlist`, `--threads`, `--extensions` | Threaded dir brute-force |
| `xss` | `--url` | `--param` | Reflected XSS detection |
| `request` | `--url` | `--method`, `--data`, `--headers`, `--follow` | Custom HTTP request |

---

## Plugin System

Write a new module and drop it in `plugins_external/`:

```python
# plugins_external/my_module.py

from typing import List
from ctf_toolkit.core.base_module import BaseModule
from ctf_toolkit.core.plugin_system import module

@module
class MyModule(BaseModule):
    MODULE_NAME = "mymodule"
    MODULE_DESCRIPTION = "My custom CTF module"

    def get_actions(self) -> List[str]:
        return ["solve", "analyze"]

    def solve(self, target: str = "", **kwargs) -> None:
        self._result.add_finding(f"Solving: {target}")
        self._result.set_data("target", target)

    def analyze(self, file: str = "", **kwargs) -> None:
        self._result.add_finding(f"Analyzing: {file}")
```

Then use it immediately:
```bash
toolkit mymodule solve --target http://example.com
```

Plugins are auto-discovered at startup. No registration needed beyond the `@module` decorator.

---

## Output & Logging

All results are saved as structured JSON in `output/`:

```json
{
  "module": "crypto",
  "action": "xor-crack",
  "success": true,
  "timestamp": "2025-01-15T10:23:01",
  "elapsed_seconds": 0.842,
  "findings": [
    "[Rank 1] Key (len=4): 43544621 | 'CTF!' ..."
  ],
  "errors": [],
  "data": {
    "key_rank_1": {
      "key_hex": "43544621",
      "key_len": 4,
      "score": 12.3,
      "plaintext": "The flag is hidden here..."
    }
  }
}
```

Logs are written to `logs/toolkit.log`.

---

## Running Tests

```bash
# Run all tests
pytest

# With coverage report
pytest --cov=ctf_toolkit --cov-report=term-missing

# Run a specific module's tests
pytest tests/test_crypto/
pytest tests/test_web/ -v
```

---

## Project Structure

```
ctf-toolkit/
├── ctf_toolkit/                  # Main package
│   ├── __init__.py               # Version info
│   ├── __main__.py               # python -m ctf_toolkit entry point
│   ├── core/
│   │   ├── cli.py                # Argument parser + main() entry point
│   │   ├── config.py             # YAML + .env configuration system
│   │   ├── logger.py             # Rich logging setup
│   │   ├── base_module.py        # BaseModule + ModuleResult
│   │   └── plugin_system.py      # PluginRegistry + @module decorator
│   ├── modules/
│   │   ├── binary/
│   │   │   └── binary_module.py  # ELF analysis, checksec, overflow, ROP
│   │   ├── crypto/
│   │   │   └── crypto_module.py  # XOR, Caesar, RSA, encoding, freq analysis
│   │   ├── stego/
│   │   │   └── stego_module.py   # LSB, metadata, file signatures, strings
│   │   └── web/
│   │       └── web_module.py     # Scan, SQLi, dir-brute, XSS, requests
│   ├── utils/
│   │   └── helpers.py            # Shared utilities (hex dump, flag finder, etc.)
│   └── plugins/                  # Internal plugin package
├── plugins_external/             # Drop your custom plugins here
│   └── example_plugin.py         # Template plugin
├── tests/
│   ├── conftest.py               # Shared pytest fixtures
│   ├── test_binary/
│   ├── test_crypto/
│   ├── test_stego/
│   └── test_web/
├── output/                       # Auto-created, stores JSON results
├── logs/                         # Auto-created, stores log files
├── wordlists/                    # Place custom wordlists here
├── config.yaml                   # Configuration file
├── .env.example                  # Environment variable template
├── requirements.txt
├── setup.py
└── README.md
```

---

## Recommended Companion Tools

Install these system tools for full functionality:

```bash
# Debian/Ubuntu
sudo apt install binutils file exiftool checksec

# ROPgadget (Python)
pip install ROPgadget

# pwntools (full binary exploitation)
pip install pwntools
```

---

## Contributing / Extending

1. Fork and clone the repository
2. Create a new module in `ctf_toolkit/modules/<name>/`
3. Inherit from `BaseModule`, use `@module` decorator
4. Add tests in `tests/test_<name>/`
5. Register actions in `get_actions()`
6. Add CLI subparser in `core/cli.py`

---

## Disclaimer

This toolkit is intended for authorized security research, CTF competitions, and educational purposes only. Do not use against systems you do not own or have explicit permission to test.

---

## License

MIT License — see LICENSE file for details.
