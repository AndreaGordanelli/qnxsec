"""Command line.

    qnxsec file <binary>          card for a single binary
    qnxsec firmware <folder>      analyse a tree (extracted firmware or live system)
"""
from __future__ import annotations

import argparse
import sys

from . import __version__, checks, firmware, report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qnxsec",
        description="Static analysis for QNX firmware and systems: protections, IPC surface, "
                    "targets to look at first. Nothing is executed.")
    parser.add_argument("--version", action="version", version=f"qnxsec {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    single = subparsers.add_parser("file", help="card for one binary")
    single.add_argument("path", help="file to analyse")
    single.add_argument("--json", action="store_true", help="JSON output")

    tree = subparsers.add_parser("firmware", help="analyse a tree of files")
    tree.add_argument("root", help="firmware folder or system root")
    tree.add_argument("--json", action="store_true", help="JSON output")
    tree.add_argument("--targets", type=int, default=15,
                      help="how many targets to list (default 15)")
    tree.add_argument("--exclude", nargs="*", default=["proc", "sys"],
                      help="folder names to skip (default: proc sys)")
    tree.add_argument("--details", action="store_true",
                      help="include the per-binary cards in the JSON output")
    return parser


def main(argv: list[str] | None = None) -> int:
    options = build_parser().parse_args(argv)

    if options.command == "file":
        entry = checks.card(options.path)
        print(report.to_json(entry) if options.json else report.card_text(entry))
        return 0

    if options.command == "firmware":
        result = firmware.analyse(options.root, options.targets, tuple(options.exclude))
        if options.json:
            print(report.to_json(result if options.details else {"summary": result["summary"]}))
        else:
            print(report.summary_text(result["summary"], options.targets))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
