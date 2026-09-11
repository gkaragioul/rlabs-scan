"""Command-line interface for rlabs-scan."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
from pathlib import Path
import sys

from .analyze import analyze
from .pe import PEFormatError, PEImage
from .report import build_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rlabs")
    commands = parser.add_subparsers(dest="command")
    scan = commands.add_parser("scan", help="inspect a Windows executable without running it")
    scan.add_argument("executable", nargs="?", help="path to a Windows .exe file")
    scan.add_argument("--output", help="write JSON to this path instead of standard output")
    scan.add_argument("--format", choices=("json",), default="json")
    scan.add_argument("--search-path", action="append", default=[], metavar="DIRECTORY")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as error:
        return int(error.code)

    if args.command != "scan" or args.executable is None:
        parser.print_usage()
        return 2

    path = Path(args.executable)
    if not path.is_file():
        print(f"rlabs: target is not a readable file: {path}", file=sys.stderr)
        return 2
    try:
        image = PEImage.from_bytes(path.read_bytes())
    except (OSError, PEFormatError) as error:
        print(f"rlabs: cannot inspect PE file: {error}", file=sys.stderr)
        return 3

    report = build_report(path, image, analyze(image, path, [Path(item) for item in args.search_path]))
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        try:
            Path(args.output).write_text(rendered, encoding="utf-8")
        except OSError as error:
            print(f"rlabs: cannot write output: {error}", file=sys.stderr)
            return 4
    else:
        print(rendered, end="")
    return 0
