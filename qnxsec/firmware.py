"""Walking a tree — an extracted firmware, a mounted image or a live QNX system.

Read-only: it looks at everything, executes nothing and writes nothing to disk.
"""
from __future__ import annotations

import os
import stat
from collections import Counter
from pathlib import Path

from . import checks

MAX_SIZE_FOR_STRINGS = 64 * 1024 * 1024


def walk_tree(root: str | Path, exclude: tuple[str, ...] = ()):
    """Walk the tree and yield (path, mode, size) for every regular file."""
    for folder, subfolders, names in os.walk(root, followlinks=False):
        subfolders.sort()
        for name in sorted(names):
            path = Path(folder) / name
            if any(part in path.parts for part in exclude):
                continue
            try:
                info = path.stat()
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            yield path, info.st_mode, info.st_size


def analyse(root: str | Path, targets: int = 15, exclude: tuple[str, ...] = (),
            progress=None) -> dict:
    """Analyse every binary in the tree and return a summary plus the per-file cards."""
    root = Path(root)
    cards, others, compressed = [], 0, 0
    count = 0
    for path, mode, size in walk_tree(root, exclude):
        count += 1
        if progress and count % 200 == 0:
            progress(count)
        entry = checks.card(path, mode, strings=size <= MAX_SIZE_FOR_STRINGS)
        if entry["file_type"] == "elf":
            cards.append(entry)
        elif entry["file_type"] == "qnx-compressed-elf":
            compressed += 1
        elif size > 0:
            others += 1
    summary = summarise(root, cards, count, compressed, others, targets)
    return {"summary": summary, "cards": cards}


def summarise(root, cards: list[dict], count: int, compressed: int, others: int,
              targets: int) -> dict:
    elfs = [entry for entry in cards if entry["file_type"] == "elf"]
    architectures = Counter(entry["architecture"] for entry in elfs)
    protections = {
        "count": len(elfs),
        "canary": sum(1 for entry in elfs if entry["protections"]["canary"]),
        "pie": sum(1 for entry in elfs if entry["protections"]["pie"]),
        "nx": sum(1 for entry in elfs if entry["protections"]["nx"] is True),
        "relro": sum(1 for entry in elfs if entry["protections"]["relro"] != "none"),
        "without_canary": sorted(entry["name"] for entry in elfs
                                 if not entry["protections"]["canary"]),
    }
    privileged = []
    for entry in sorted(cards, key=lambda item: -item["score"]):
        if not (entry["setuid"] or entry["setgid"]):
            continue
        kind = "setuid" if entry["setuid"] else "setgid"
        missing = ", ".join(entry["missing_protections"]) or "nothing"
        privileged.append(f"{entry['name']} ({entry['architecture']}, {kind}) "
                          f"missing: {missing}")
    surface = Counter(item["label"] for entry in elfs for item in entry["surface"])
    hints = Counter(item["label"] for entry in elfs for item in entry["hints"])
    ranked = []
    for entry in sorted(elfs, key=lambda item: (-item["score"], item["name"])):
        if not entry["target"]:
            continue
        missing = ", ".join(entry["missing_protections"]) or "nothing"
        surface_item = ", ".join(item["label"] for item in entry["surface"][:2]) or "—"
        privilege = " setuid" if entry["setuid"] else ""
        ranked.append(f"{entry['score']:>3}  {entry['name']} ({entry['architecture']},"
                      f"{privilege}) — missing: {missing} — {surface_item}")
    return {
        "root": str(root),
        "files": count,
        "elf": len(elfs),
        "compressed": compressed,
        "other_binaries": others,
        "architectures": dict(architectures),
        "protections": protections,
        "privileged": privileged,
        "targets": ranked[:targets],
        "targets_total": len(ranked),
        "surface": dict(surface),
        "hints": dict(hints),
    }
