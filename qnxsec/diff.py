"""Compare two builds of the same binary: what a vendor change actually touched.

Two builds of one component differ by a handful of functions, and after a
security release the question is which ones.  The comparison is by symbol, not by
whole-file hash: functions are matched by name and their bodies hashed, so a
change in the file layout does not read as "everything changed".

    qnxsec diff old.so new.so

Symbols come from ``.symtab`` when the file carries it (QNX ships a ``.sym``
sidecar next to every binary, and the vendor's own builds keep it) and from
``.dynsym`` otherwise, which still names the exported functions.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from qnxsec import elf

__all__ = ["DiffError", "FunctionChange", "compare", "render"]

# the protection flags worth reporting when they differ; "pie" means something
# only for a program, so a change there on a shared object is reported as-is and
# left to the reader
PROTECTIONS = ("pie", "nx", "canary", "fortify", "relro")


class DiffError(Exception):
    """Raised when the two files cannot be compared at all."""


@dataclass
class FunctionChange:
    """One function that differs between the two builds."""

    name: str
    status: str                     # added | removed | changed
    old_size: int = 0
    new_size: int = 0

    def __str__(self) -> str:
        if self.status == "changed" and self.old_size != self.new_size:
            return f"{self.name} ({self.old_size} -> {self.new_size} bytes)"
        return self.name

    def as_dict(self) -> dict:
        return {"name": self.name, "status": self.status, "old_size": self.old_size,
                "new_size": self.new_size}


def _digests(binary: elf.Elf) -> dict[str, tuple[dict, str | None]]:
    """``{name: (symbol, sha256 of the body or None)}`` for every function."""
    found: dict[str, tuple[dict, str | None]] = {}
    for name, symbol in binary.function_symbols().items():
        body = binary.function_body(symbol)
        found[name] = (symbol, hashlib.sha256(body).hexdigest() if body is not None else None)
    return found


def _references_masked(binary: elf.Elf, symbol: dict, body: bytes) -> bytes:
    """The body with the rel32 operand of every direct call/jmp zeroed.

    A call or jump inside a shared object is a displacement to an address that
    moves when anything above it grows, so two builds of the same function differ
    in those four bytes while the code is the same.  Masking the operands whose
    target lands inside this file's mapped bytes turns an address shift into a
    no-op, which is what lets it be told apart from a code change.

    Two forms carry such a reference: a direct call/jump (``E8``/``E9`` followed by
    the displacement) and a RIP-relative operand (a ModRM byte with ``mod=00`` and
    ``rm=101``, which is how a shared object reaches its own data).  This is a
    heuristic on purpose: a build that changes *which* in-file address an
    instruction reaches, and nothing else, is reported as relocated rather than
    changed -- and the two are one line apart in the output, so the reader can
    tell.
    """
    masked = bytearray(body)
    base = symbol["value"]
    for offset in range(1, len(masked) - 3):
        previous = masked[offset - 1]
        direct = previous in (0xE8, 0xE9)               # call rel32, jmp rel32
        rip_relative = (previous & 0xC7) == 0x05        # ModRM mod=00, rm=101
        if not (direct or rip_relative):
            continue
        displacement = int.from_bytes(masked[offset:offset + 4], "little", signed=True)
        if binary.offset_of(base + offset + 4 + displacement) is not None:
            masked[offset:offset + 4] = b"\0\0\0\0"
    return bytes(masked)


def compare(old_path, new_path) -> dict:
    """Compare two binaries and return the differences as plain data.

    Raises :class:`DiffError` when the two files are not comparable (different
    architectures, or not ELF at all).
    """
    old = elf.Elf(old_path)
    new = elf.Elf(new_path)
    if old.architecture != new.architecture:
        raise DiffError(f"different architectures: {old.architecture} vs {new.architecture}")

    old_bodies = _digests(old)
    new_bodies = _digests(new)

    added: list[FunctionChange] = []
    removed: list[FunctionChange] = []
    changed: list[FunctionChange] = []
    relocated: list[FunctionChange] = []
    identical = 0

    for name, (symbol, digest) in new_bodies.items():
        if name not in old_bodies:
            added.append(FunctionChange(name, "added", new_size=symbol["size"]))
            continue
        old_symbol, old_digest = old_bodies[name]
        if old_digest is None or digest is None or old_digest != digest:
            change = FunctionChange(name, "changed", old_symbol["size"], symbol["size"])
            # same size and equal once the in-file references are masked: an
            # address shift, not a code change
            if old_symbol["size"] == symbol["size"]:
                old_body = old.function_body(old_symbol)
                new_body = new.function_body(symbol)
                if (old_body is not None and new_body is not None
                        and _references_masked(old, old_symbol, old_body)
                        == _references_masked(new, symbol, new_body)):
                    change.status = "relocated"
                    relocated.append(change)
                    continue
            changed.append(change)
        else:
            identical += 1

    for name, (symbol, _) in old_bodies.items():
        if name not in new_bodies:
            removed.append(FunctionChange(name, "removed", old_size=symbol["size"]))

    protections = {name: (getattr(old, name), getattr(new, name)) for name in PROTECTIONS
                   if getattr(old, name) != getattr(new, name)}
    needed = {"added": sorted(set(new.needed) - set(old.needed)),
              "removed": sorted(set(old.needed) - set(new.needed))}

    return {
        "old": str(old_path),
        "new": str(new_path),
        "architecture": new.architecture,
        "size": {"old": old.size, "new": new.size},
        "functions": {
            "compared": len(new_bodies),
            "identical": identical,
            "added": added,
            "removed": removed,
            "changed": changed,
            "relocated": relocated,
        },
        "protections": protections,
        "needed": needed,
    }


def _lines(changes: list[FunctionChange], limit: int) -> list[str]:
    shown = [f"    {change}" for change in changes[:limit]]
    if len(changes) > limit:
        shown.append(f"    ... and {len(changes) - limit} more")
    return shown


def render(diff: dict, limit: int = 40) -> str:
    """The text report for :func:`compare`."""
    functions = diff["functions"]
    out = [f"{diff['old']}  ->  {diff['new']}",
           f"  {diff['architecture']}, {diff['size']['old']} -> {diff['size']['new']} bytes, "
           f"{functions['compared']} functions"]
    for title, key in (("changed", "changed"), ("added", "added"), ("removed", "removed"),
                       ("same code, references moved", "relocated")):
        changes = functions[key]
        out.append(f"  {title}: {len(changes)}")
        out.extend(_lines(changes, limit))
    out.append(f"  identical: {functions['identical']}")
    if diff["protections"]:
        out.append("  protections that changed:")
        for name, (before, after) in sorted(diff["protections"].items()):
            out.append(f"    {name}: {before} -> {after}")
    if diff["needed"]["added"] or diff["needed"]["removed"]:
        out.append("  libraries linked:")
        for name in diff["needed"]["added"]:
            out.append(f"    + {name}")
        for name in diff["needed"]["removed"]:
            out.append(f"    - {name}")
    if functions["relocated"]:
        out.append("  (relocated: same size, and equal once every reference into this file is"
                   "\n   masked.  Usually an address shift; it is also what a call retargeted"
                   "\n   to another function of the same file looks like, which this cannot"
                   "\n   tell apart without a disassembler.)")
    if not any(functions[key] for key in ("changed", "added", "removed")):
        out.append("  no function differs: the two builds are the same code")
    return "\n".join(out)


def as_dict(diff: dict) -> dict:
    """The diff as JSON-friendly data (the dataclasses turned into dictionaries)."""
    functions = dict(diff["functions"])
    for key in ("added", "removed", "changed", "relocated"):
        functions[key] = [change.as_dict() for change in functions[key]]
    return {**diff, "functions": functions}
