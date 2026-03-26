"""
CLI entry point for CTF Toolkit.
Parses commands of the form: toolkit <module> <action> [options]
"""

import sys
import argparse
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.text import Text

from ctf_toolkit.core.config import config
from ctf_toolkit.core.logger import setup_root_logger, get_logger
from ctf_toolkit.core.plugin_system import PluginRegistry
from ctf_toolkit import __version__

console = Console()
logger = get_logger("ctf_toolkit.cli")

BANNER = r"""
  ██████╗████████╗███████╗    ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
 ██╔════╝╚══██╔══╝██╔════╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
 ██║        ██║   █████╗         ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║
 ██║        ██║   ██╔══╝         ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║
 ╚██████╗   ██║   ██║            ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║
  ╚═════╝   ╚═╝   ╚═╝            ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝
"""


def print_banner() -> None:
    console.print(f"[bold cyan]{BANNER}[/]")
    console.print(
        f"  [dim]v{__version__} | Binary · Crypto · Stego · Web[/]\n"
    )


def print_module_list() -> None:
    """Print all registered modules and their actions."""
    table = Table(
        title="[bold]Available Modules[/]",
        box=box.ROUNDED,
        border_style="cyan",
        show_lines=True,
    )
    table.add_column("Module", style="bold cyan", width=12)
    table.add_column("Description", style="white")
    table.add_column("Actions", style="green")

    for name in PluginRegistry.list_modules():
        cls = PluginRegistry.get(name)
        if cls:
            instance = cls()
            actions = ", ".join(instance.get_actions())
            table.add_row(name, cls.MODULE_DESCRIPTION, actions)

    console.print(table)
    console.print(
        "\n[dim]Usage:[/] [bold]toolkit [cyan]<module>[/] [green]<action>[/] [options]\n"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="toolkit",
        description="CTF Toolkit - Modular security research framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  toolkit crypto xor-crack --file encrypted.bin
  toolkit crypto caesar-brute --text "Khoor Zruog"
  toolkit crypto rsa-attack --n 3233 --e 17 --c 2790
  toolkit binary elf-info --binary ./vuln
  toolkit binary overflow-detect --binary ./vuln
  toolkit stego lsb-extract --image flag.png
  toolkit stego metadata --file suspicious.jpg
  toolkit web scan --url http://target.com
  toolkit web sqli --url "http://target.com/page?id=1"
  toolkit web dir-brute --url http://target.com --wordlist wordlists/common.txt
        """,
    )

    parser.add_argument(
        "--version", action="version", version=f"CTF Toolkit v{__version__}"
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
        help="Override log level",
    )
    parser.add_argument(
        "--output-dir", default=None, help="Override output directory"
    )
    parser.add_argument(
        "--save", action="store_true", help="Save results to output directory"
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable colored output"
    )
    parser.add_argument("--list", action="store_true", help="List all modules and actions")

    subparsers = parser.add_subparsers(dest="module", metavar="<module>")

    # ── crypto ──────────────────────────────────────────────────────────────
    crypto = subparsers.add_parser("crypto", help="Cryptography attacks and utilities")
    crypto_sub = crypto.add_subparsers(dest="action", metavar="<action>")

    xor = crypto_sub.add_parser("xor-crack", help="XOR key brute-force")
    xor.add_argument("--file", help="Input file path")
    xor.add_argument("--text", help="Hex-encoded or raw ciphertext string")
    xor.add_argument("--max-keylen", type=int, default=16)
    xor.add_argument("--hex", action="store_true", help="Input is hex-encoded")

    caesar = crypto_sub.add_parser("caesar-brute", help="Caesar / ROT cipher brute-force")
    caesar.add_argument("--text", required=True)
    caesar.add_argument("--all", action="store_true", help="Show all 25 rotations")

    rsa = crypto_sub.add_parser("rsa-attack", help="RSA attack utilities")
    rsa.add_argument("--n", type=int)
    rsa.add_argument("--e", type=int)
    rsa.add_argument("--c", type=int, help="Ciphertext")
    rsa.add_argument("--attack", choices=["small-e", "factor", "wiener"], default="small-e")

    encode = crypto_sub.add_parser("encode", help="Encoding utilities")
    encode.add_argument("--input", required=True)
    encode.add_argument(
        "--scheme",
        choices=["base64", "base32", "hex", "url", "rot13"],
        required=True,
    )
    encode.add_argument("--decode", action="store_true", help="Decode instead of encode")

    freq = crypto_sub.add_parser("freq-analysis", help="Frequency analysis on ciphertext")
    freq.add_argument("--file", help="Input file")
    freq.add_argument("--text", help="Input text")

    # ── binary ───────────────────────────────────────────────────────────────
    binary = subparsers.add_parser("binary", help="Binary exploitation utilities")
    binary_sub = binary.add_subparsers(dest="action", metavar="<action>")

    elf = binary_sub.add_parser("elf-info", help="ELF binary analysis")
    elf.add_argument("--binary", required=True)

    overflow = binary_sub.add_parser("overflow-detect", help="Buffer overflow detection")
    overflow.add_argument("--binary", required=True)
    overflow.add_argument("--max-size", type=int, default=512)

    rop = binary_sub.add_parser("rop-gadgets", help="ROP gadget search")
    rop.add_argument("--binary", required=True)
    rop.add_argument("--type", choices=["all", "ret", "pop", "syscall"], default="all")

    checksec = binary_sub.add_parser("checksec", help="Check binary security flags")
    checksec.add_argument("--binary", required=True)

    # ── stego ─────────────────────────────────────────────────────────────────
    stego = subparsers.add_parser("stego", help="Steganography analysis tools")
    stego_sub = stego.add_subparsers(dest="action", metavar="<action>")

    lsb = stego_sub.add_parser("lsb-extract", help="LSB steganography extraction")
    lsb.add_argument("--image", required=True)
    lsb.add_argument("--bits", type=int, default=1)
    lsb.add_argument("--channel", choices=["R", "G", "B", "A", "all"], default="all")

    meta = stego_sub.add_parser("metadata", help="Extract file metadata")
    meta.add_argument("--file", required=True)

    filesig = stego_sub.add_parser("file-sig", help="Detect file signature / magic bytes")
    filesig.add_argument("--file", required=True)

    strings_cmd = stego_sub.add_parser("strings", help="Extract printable strings")
    strings_cmd.add_argument("--file", required=True)
    strings_cmd.add_argument("--min-length", type=int, default=4)

    # ── web ───────────────────────────────────────────────────────────────────
    web = subparsers.add_parser("web", help="Web exploitation utilities")
    web_sub = web.add_subparsers(dest="action", metavar="<action>")

    scan = web_sub.add_parser("scan", help="Full web target scan")
    scan.add_argument("--url", required=True)
    scan.add_argument("--headers", nargs="*", help="Extra headers key:value")

    sqli = web_sub.add_parser("sqli", help="SQL injection detection")
    sqli.add_argument("--url", required=True)
    sqli.add_argument("--param", help="Specific parameter to test")
    sqli.add_argument("--method", choices=["GET", "POST"], default="GET")

    dirb = web_sub.add_parser("dir-brute", help="Directory brute-forcing")
    dirb.add_argument("--url", required=True)
    dirb.add_argument("--wordlist", default=None)
    dirb.add_argument("--threads", type=int, default=10)
    dirb.add_argument("--extensions", nargs="*", default=["", ".php", ".html", ".txt"])

    xss = web_sub.add_parser("xss", help="XSS vulnerability detection")
    xss.add_argument("--url", required=True)
    xss.add_argument("--param", help="Parameter to test")

    req = web_sub.add_parser("request", help="Custom HTTP request")
    req.add_argument("--url", required=True)
    req.add_argument("--method", choices=["GET", "POST", "PUT", "DELETE", "HEAD"], default="GET")
    req.add_argument("--data", help="POST body (key=val&key2=val2)")
    req.add_argument("--headers", nargs="*")
    req.add_argument("--follow", action="store_true", help="Follow redirects")

    return parser


def main(args: Optional[List[str]] = None) -> int:
    """
    Main CLI entry point.

    Returns:
        Exit code (0 = success, 1 = error)
    """
    # Bootstrap: load modules, set up logging
    PluginRegistry.load_builtin_modules()
    PluginRegistry.load_plugin_dir(config.get("toolkit", "plugins_dir", default="plugins_external"))

    log_level = config.get("toolkit", "log_level", default="INFO")
    log_file = config.get("toolkit", "log_file", default="logs/toolkit.log")
    setup_root_logger(level=log_level, log_file=log_file)

    parser = build_parser()
    parsed = parser.parse_args(args)

    # Apply overrides
    if parsed.log_level:
        config.set("toolkit", "log_level", value=parsed.log_level)
    if parsed.output_dir:
        config.set("toolkit", "output_dir", value=parsed.output_dir)

    if parsed.no_color:
        console._force_terminal = False  # type: ignore

    # No module given: print banner + help
    if not parsed.module:
        print_banner()
        if parsed.list:
            print_module_list()
        else:
            parser.print_help()
        return 0

    # Get module
    module_cls = PluginRegistry.get(parsed.module)
    if not module_cls:
        console.print(f"[red]Unknown module: '{parsed.module}'[/]")
        console.print(f"Available: {', '.join(PluginRegistry.list_modules())}")
        return 1

    # No action given: print module help
    action = getattr(parsed, "action", None)
    if not action:
        # Print subparser help for the module
        for action_name, subparser in parser._subparsers._actions:  # type: ignore
            pass
        parser.parse_args([parsed.module, "--help"])
        return 0

    # Build kwargs from parsed namespace
    kwargs = {
        k: v for k, v in vars(parsed).items()
        if k not in ("module", "action", "log_level", "output_dir", "save", "no_color", "list")
        and v is not None
    }

    # Run module
    instance = module_cls()
    result = instance.run(action, **kwargs)
    instance.print_findings(result)

    # Save if requested or configured
    if parsed.save or config.get("toolkit", "auto_save"):
        instance.save_result(result)

    return 0 if result.success else 1


if __name__ == "__main__":
    sys.exit(main())
