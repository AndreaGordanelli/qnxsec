"""Who publishes what: the IPC surface of a firmware.

QNX processes talk through names in the filesystem (/dev/... resource managers) and
through PPS objects (/pps/...). A binary that calls resmgr_attach or name_attach is
*publishing* a name; a binary that only mentions the path in its strings is *using* it.

The mapping is a heuristic and it says so: strings give the names, symbols give the
direction. What it produces is a graph to reason about, not a proof.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from . import checks

PUBLISHING_SYMBOLS = ("resmgr_attach", "name_attach", "iofunc_", "dispatch_", "message_attach")
DEVICE_NAME = re.compile(r"^/(dev|pps)/[A-Za-z0-9_.:/-]{1,60}$")


@dataclass
class Publisher:
    """A binary that attaches to the namespace."""
    binary: str
    architecture: str = ""
    names: list[str] = field(default_factory=list)
    symbols: list[str] = field(default_factory=list)


@dataclass
class Surface:
    """The whole picture: who publishes, who uses, and how they connect."""
    publishers: list[Publisher] = field(default_factory=list)
    users: dict[str, list[str]] = field(default_factory=dict)      # name -> binaries
    names: Counter = field(default_factory=Counter)                # name -> how many mention it
    unclaimed: list[str] = field(default_factory=list)             # used but not published here

    def summary(self) -> dict:
        return {
            "publishers": [{"binary": item.binary, "architecture": item.architecture,
                            "names": item.names, "symbols": item.symbols}
                           for item in self.publishers],
            "names": dict(self.names.most_common()),
            "unclaimed": sorted(self.unclaimed),
            "users": {name: binaries for name, binaries in sorted(self.users.items())},
        }

    def to_dot(self) -> str:
        lines = ["digraph surface {", '  rankdir="LR";',
                 '  node [shape=box, style=rounded, fontname="monospace"];',
                 '  edge [fontname="monospace"];']
        for item in self.publishers:
            lines.append(f'  "{item.binary}" [label="{item.binary}\\n({item.architecture})",'
                         ' style="rounded,filled", fillcolor="#cfe3ff"];')
        for name, binaries in sorted(self.users.items()):
            lines.append(f'  "{name}" [shape=ellipse, fillcolor="#ffe8b0", '
                         'style=filled];')
            for binary in binaries:
                if binary not in {publisher.binary for publisher in self.publishers}:
                    lines.append(f'  "{binary}";')
                lines.append(f'  "{binary}" -> "{name}" [label="uses"];')
        for item in self.publishers:
            for name in item.names:
                lines.append(f'  "{item.binary}" -> "{name}" [label="publishes", '
                             'color="#1a6b1a", fontcolor="#1a6b1a"];')
        lines.append("}")
        return "\n".join(lines)

    def to_mermaid(self) -> str:
        lines = ["graph LR"]
        safe = lambda text: re.sub(r"[^A-Za-z0-9_]", "_", text)      # noqa: E731
        for item in self.publishers:
            lines.append(f'  {safe(item.binary)}["{item.binary}"]')
        for name, binaries in sorted(self.users.items()):
            lines.append(f'  {safe(name)}(("{name}"))')
            for binary in binaries:
                lines.append(f'  {safe(binary)} --> {safe(name)}')
        for item in self.publishers:
            for name in item.names:
                lines.append(f'  {safe(item.binary)} == "{name}" ==> {safe(name)}')
        return "\n".join(lines)


def names_in(card: dict) -> list[str]:
    """Device and PPS names mentioned by a binary, from its strings."""
    found = []
    for hint in card.get("hints", []):
        text = hint.get("string", "")
        if DEVICE_NAME.match(text):
            found.append(text)
    return sorted(set(found))


def from_cards(cards: list[dict]) -> Surface:
    """Build the surface map from the per-binary cards of a scan."""
    surface = Surface()
    for card in cards:
        if card.get("file_type") != "elf":
            continue
        names = names_in(card)
        symbols = sorted(item["symbol"] for item in card.get("surface", []))
        publishes = [symbol for symbol in symbols if symbol.startswith(PUBLISHING_SYMBOLS)]
        if names and publishes:
            surface.publishers.append(Publisher(binary=card["name"],
                                                architecture=card.get("architecture", ""),
                                                names=names, symbols=publishes))
        for name in names:
            surface.names[name] += 1
            surface.users.setdefault(name, []).append(card["name"])
    published = {name for publisher in surface.publishers for name in publisher.names}
    surface.unclaimed = sorted(name for name in surface.names if name not in published)
    return surface


def from_directory(root: str, exclude: tuple[str, ...] = ()) -> Surface:
    """Scan a directory and build the surface map (convenience for the CLI)."""
    from . import firmware

    return from_cards(firmware.analyse(root, exclude=exclude)["cards"])


def report(surface: Surface, limit: int = 20) -> str:
    lines = [f"Publishers: {len(surface.publishers)}"]
    for publisher in surface.publishers[:limit]:
        names = ", ".join(publisher.names[:6]) or "no name in strings"
        lines.append(f"  {publisher.binary} ({publisher.architecture}) → {names}")
        lines.append(f"      symbols: {', '.join(publisher.symbols)}")
    lines.append("")
    lines.append("SIGNALS")
    if surface.names:
        lines.append("  most mentioned names:")
        for name, count in surface.names.most_common(limit):
            lines.append(f"    - {name} ({count})")
    if surface.unclaimed:
        lines.append(f"  used but not published by anything in the scan ({len(surface.unclaimed)}):")
        for name in surface.unclaimed[:limit]:
            lines.append(f"    - {name}")
    return "\n".join(lines)


def surface_of_binary(card: dict) -> list[str]:
    """Convenience: the QNX surface labels of one card."""
    return [item["label"] for item in checks.card(card.get("path", ""))["surface"]] \
        if card.get("path") else []
