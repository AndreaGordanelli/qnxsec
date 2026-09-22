"""Command line.

    qnxsec file <binary>            card for a single binary
    qnxsec firmware <folder>        analyse a tree (extracted firmware or live system)
    qnxsec ifs <image or dump>      list and extract the IFS images inside a file
    qnxsec bootscript <file>        signals in a boot script or buildfile
    qnxsec compressed <file>        structure of a compressed QNX ELF (iwlyfmbp)
    qnxsec surface <folder>         who publishes which QNX name (graph exports)
    qnxsec dump <firmware dump>     the whole pipeline: find, extract, analyse, map
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, bootscript, checks, deflate, firmware, ifs, report, surface


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qnxsec",
        description="Static analysis for QNX firmware and systems: protections, IPC surface, "
                    "boot script, targets to look at first. Nothing is executed.")
    parser.add_argument("--version", action="version", version=f"qnxsec {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    single = subparsers.add_parser("file", help="card for one binary")
    single.add_argument("path")
    single.add_argument("--json", action="store_true")

    tree = subparsers.add_parser("firmware", help="analyse a tree of files")
    tree.add_argument("root")
    tree.add_argument("--json", action="store_true")
    tree.add_argument("--targets", type=int, default=15)
    tree.add_argument("--exclude", nargs="*", default=["proc", "sys"])
    tree.add_argument("--details", action="store_true",
                      help="include the per-binary cards in the JSON output")

    images = subparsers.add_parser("ifs", help="list and extract IFS images inside a file")
    images.add_argument("path", help="firmware dump or a raw IFS image")
    images.add_argument("--json", action="store_true")
    images.add_argument("--extract", metavar="DIR", help="extract the images into DIR")
    images.add_argument("--script", action="store_true",
                        help="print the boot script of every image found")

    script = subparsers.add_parser("bootscript", help="signals in a boot script or buildfile")
    script.add_argument("path", help="text file with the script, or an IFS image")
    script.add_argument("--json", action="store_true")

    compressed = subparsers.add_parser("compressed", help="structure of an iwlyfmbp container")
    compressed.add_argument("path")
    compressed.add_argument("--json", action="store_true")

    mapping = subparsers.add_parser("surface", help="who publishes which QNX name")
    mapping.add_argument("root")
    mapping.add_argument("--json", action="store_true")
    mapping.add_argument("--dot", metavar="FILE", help="write the graph in Graphviz format")
    mapping.add_argument("--mermaid", metavar="FILE", help="write the graph in Mermaid format")
    mapping.add_argument("--exclude", nargs="*", default=["proc", "sys"])

    dump = subparsers.add_parser("dump", help="full pipeline over a firmware dump")
    dump.add_argument("path", help="file with one or more IFS images inside")
    dump.add_argument("--extract", metavar="DIR", help="where to unpack (default: none)")
    dump.add_argument("--json", action="store_true")
    dump.add_argument("--targets", type=int, default=15)
    return parser


def _do_file(options) -> int:
    entry = checks.card(options.path)
    print(report.to_json(entry) if options.json else report.card_text(entry))
    return 0


def _do_firmware(options) -> int:
    result = firmware.analyse(options.root, options.targets, tuple(options.exclude))
    if options.json:
        print(report.to_json(result if options.details else {"summary": result["summary"]}))
    else:
        print(report.summary_text(result["summary"], options.targets))
    return 0


def _do_ifs(options) -> int:
    images = ifs.images_in_file(options.path)
    if not images:
        print("No IFS image found in this file.")
        return 1
    summaries = []
    for index, image in enumerate(images):
        chained = ifs.follow_chain(image)
        summaries.append({"summary": image.summary(),
                          "entries": [entry.as_dict() for entry in image.entries],
                          "chained_images": len(chained) - 1})
        if options.json:
            continue
        print(f"Image {index + 1} at offset {image.offset:#x}"
              + (f" (chained: {len(chained) - 1} more)" if len(chained) > 1 else ""))
        info = image.summary()
        print(f"  entries: {info['entries']} · {info['kinds']}")
        print(f"  mountpoint: {info['mountpoint'] or '(none)'} · "
              f"script: {info['script'] or '(none)'}")
        if info["privileged"]:
            print("  privileged: " + ", ".join(info["privileged"]))
        print(f"  files ({len(image.files)}), directories ({len(image.directories)}), "
              f"symlinks ({len(image.symlinks)}), devices ({len(image.devices)})")
        if options.script:
            entry = image.script()
            if entry:
                text = image.read(entry).decode("utf-8", "replace")
                print(bootscript.report(bootscript.parse(text)))
    if options.extract:
        for index, image in enumerate(images):
            destination = Path(options.extract) / f"image{index + 1}"
            result = image.extract(destination)
            print(f"extracted {result['written']} entries into {destination}")
            if result["failed"]:
                print(f"  failures: {len(result['failed'])}")
    if options.json:
        print(report.to_json(summaries))
    return 0


def _do_bootscript(options) -> int:
    path = Path(options.path)
    data = path.read_bytes()
    text = None
    if data.startswith(b"\x7fELF") is False and b"[+script]" in data[:65536]:
        text = data.decode("utf-8", "replace")
    if text is None:
        for image in ifs.images_in_file(path):
            entry = image.script()
            if entry:
                text = image.read(entry).decode("utf-8", "replace")
                break
    if text is None:
        print("No boot script found (neither text nor inside an IFS image).")
        return 1
    build = bootscript.parse(text)
    print(report.to_json(build.summary()) if options.json else bootscript.report(build))
    return 0


def _do_compressed(options) -> int:
    container = deflate.parse_file(options.path)
    if options.json:
        print(report.to_json(container.as_dict()))
        return 0
    print(f"{options.path}")
    print(f"  compression: {container.compression} · block size: {container.block_size}")
    print(f"  uncompressed: {container.declared_size} bytes in {len(container.blocks)} blocks"
          f" · stored: {container.total_compressed} bytes")
    print(f"  blocks add up: {'yes' if container.complete else 'NO'}"
          f" · ratio: {container.compression_ratio}")
    for block in container.blocks[:12]:
        print(f"    #{block.index} at {block.offset:#x}: {block.size} bytes -> "
              f"{block.data_size} stored")
    if len(container.blocks) > 12:
        print(f"    ... and {len(container.blocks) - 12} more")
    return 0


def _do_surface(options) -> int:
    found = surface.from_directory(options.root, tuple(options.exclude))
    if options.dot:
        Path(options.dot).write_text(found.to_dot(), encoding="utf-8")
        print(f"Graphviz graph written to {options.dot}")
    if options.mermaid:
        Path(options.mermaid).write_text(found.to_mermaid(), encoding="utf-8")
        print(f"Mermaid graph written to {options.mermaid}")
    if options.json:
        print(report.to_json(found.summary()))
    elif not (options.dot or options.mermaid):
        print(surface.report(found))
    return 0


def _do_dump(options) -> int:
    images = ifs.images_in_file(options.path)
    if not images:
        print("No IFS image found in this file.")
        return 1
    result: dict = {"path": options.path, "images": []}
    for index, image in enumerate(images):
        info = {"summary": image.summary(), "analyses": [], "script": None, "surface": None}
        parsed_script = None
        entry = image.script()
        if entry:
            try:
                parsed_script = bootscript.parse(image.read(entry).decode("utf-8", "replace"))
                info["script"] = parsed_script.summary()
            except bootscript.ScriptError:
                pass
        if options.extract:
            destination = Path(options.extract) / f"image{index + 1}"
            info["extracted"] = image.extract(destination)["written"]
            analyse_root = str(destination)
        else:
            analyse_root = ""
        if analyse_root:
            analysis = firmware.analyse(analyse_root, options.targets)
            info["analyses"] = analysis["summary"]
            info["surface"] = surface.from_cards(analysis["cards"]).summary()
        result["images"].append(info)
        if not options.json:
            print(f"Image {index + 1} at offset {image.offset:#x}: {info['summary']['entries']} "
                  f"entries, script: {info['summary']['script'] or '(none)'}")
            if parsed_script is not None:
                print(bootscript.report(parsed_script))
            if info.get("extracted"):
                print(f"  extracted {info['extracted']} entries"
                      + (f" into {options.extract}/image{index + 1}" if options.extract else ""))
            if info["analyses"]:
                print(report.summary_text(info["analyses"], options.targets))
            if info["surface"]:
                print()
                print(surface.report(_surface_from_summary(info["surface"])))
    if options.json:
        print(report.to_json(result))
    return 0


def _surface_from_summary(summary: dict) -> surface.Surface:
    """Rebuild a Surface object from its summary, for rendering only."""
    found = surface.Surface()
    found.names.update(summary.get("names", {}))
    found.unclaimed = list(summary.get("unclaimed", []))
    for item in summary.get("publishers", []):
        found.publishers.append(surface.Publisher(binary=item["binary"],
                                                  architecture=item.get("architecture", ""),
                                                  names=item.get("names", []),
                                                  symbols=item.get("symbols", [])))
    return found


def main(argv: list[str] | None = None) -> int:
    options = build_parser().parse_args(argv)
    handlers = {"file": _do_file, "firmware": _do_firmware, "ifs": _do_ifs,
                "bootscript": _do_bootscript, "compressed": _do_compressed,
                "surface": _do_surface, "dump": _do_dump}
    handler = handlers.get(options.command)
    if handler is None:
        return 1
    return handler(options)


if __name__ == "__main__":
    sys.exit(main())
