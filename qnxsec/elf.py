"""Minimal ELF reader, standard library only.

Enough to look at the binaries inside a QNX firmware without external dependencies:
header, segments (for NX and RELRO), sections, dynamic symbols (for stack canaries and
QNX surface), required libraries and notable strings.

Read-only: nothing is ever executed.
"""
from __future__ import annotations

import re
import struct
from pathlib import Path

MAGIC = b"\x7fELF"
QNX_COMPRESSED_MAGIC = b"iwlyfmbp"          # compressed QNX ELF (LZO/UCL)

_STRING_PATTERNS: dict[int, re.Pattern] = {}


def _string_pattern(minimum: int) -> re.Pattern:
    """Printable-string pattern, compiled once per minimum length."""
    if minimum not in _STRING_PATTERNS:
        _STRING_PATTERNS[minimum] = re.compile(rb"[\x20-\x7e]{%d,}" % max(1, minimum))
    return _STRING_PATTERNS[minimum]


BYTE_ORDER = {1: "<", 2: ">"}
CLASS = {1: 32, 2: 64}
FILE_TYPE = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
MACHINES = {
    3: "x86", 8: "mips", 20: "ppc", 21: "ppc64", 40: "arm", 42: "sh",
    50: "ia64", 62: "x86-64", 183: "aarch64", 243: "riscv",
}
# segments we care about
PT_INTERP, PT_DYNAMIC, PT_GNU_STACK, PT_GNU_RELRO = 3, 2, 0x6474E551, 0x6474E552
PF_X, PF_W, PF_R = 1, 2, 4
SHT_SYMTAB, SHT_DYNSYM, SHT_STRTAB = 2, 11, 3
# dynamic entries
DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH, DT_BIND_NOW, DT_FLAGS = 1, 14, 15, 29, 24, 30
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW, DF_1_NOW = 0x8, 0x1
SHT_NOTE = 7


class ElfError(Exception):
    """The file is not a readable ELF."""


class Elf:
    """An ELF file held in memory, parsed just far enough to be useful."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        if len(self.data) < 64 or not self.data.startswith(MAGIC):
            raise ElfError("not an ELF file")
        self.compressed = self.data.startswith(QNX_COMPRESSED_MAGIC)
        if self.compressed:
            raise ElfError("compressed QNX ELF (iwlyfmbp): decompress it first")

        self.elf_class = CLASS.get(self.data[4], 0)
        self.order = BYTE_ORDER.get(self.data[5], "")
        if not self.elf_class or not self.order:
            raise ElfError("unknown class or byte order")
        self.size = len(self.data)
        self._read_header()
        self._read_segments()
        self._read_sections()
        self._read_symbols()
        self._read_dynamic()

    # ------------------------------------------------------------------ basics

    def _unpack(self, fmt: str, offset: int):
        size = struct.calcsize(fmt)
        if offset + size > len(self.data):
            raise ElfError("structure past the end of the file")
        return struct.unpack_from(self.order + fmt, self.data, offset)

    def _read_header(self) -> None:
        if self.elf_class == 64:
            (self.file_type, self.machine, _, self.entry, self.phoff, self.shoff, self.flags,
             _, self.phentsize, self.phnum, self.shentsize, self.shnum,
             self.shstrndx) = self._unpack("HHIQQQIHHHHHH", 16)
        else:
            (self.file_type, self.machine, _, self.entry, self.phoff, self.shoff, self.flags,
             _, self.phentsize, self.phnum, self.shentsize, self.shnum,
             self.shstrndx) = self._unpack("HHIIIIIHHHHHH", 16)

    def _read_segments(self) -> None:
        self.segments = []
        for index in range(self.phnum):
            offset = self.phoff + index * self.phentsize
            try:
                if self.elf_class == 64:
                    kind, flags, off, vaddr, _, filesz, memsz, _ = self._unpack("IIQQQQQQ", offset)
                else:
                    kind, off, vaddr, _, filesz, memsz, flags, _ = self._unpack("IIIIIIII", offset)
            except ElfError:
                break
            self.segments.append({"type": kind, "flags": flags, "offset": off, "vaddr": vaddr,
                                  "filesz": filesz, "memsz": memsz})

    def _read_sections(self) -> None:
        self.sections = []
        if not self.shoff:
            return
        for index in range(self.shnum):
            offset = self.shoff + index * self.shentsize
            try:
                if self.elf_class == 64:
                    (name, kind, flags, addr, off, size, link, info, align,
                     entsize) = self._unpack("IIQQQQIIQQ", offset)
                else:
                    (name, kind, flags, addr, off, size, link, info, align,
                     entsize) = self._unpack("IIIIIIIIII", offset)
            except ElfError:
                break
            self.sections.append({"name_off": name, "type": kind, "flags": flags, "addr": addr,
                                  "offset": off, "size": size, "link": link, "info": info,
                                  "align": align, "entsize": entsize, "name": ""})

        # section names
        if self.shstrndx < len(self.sections):
            base = self.sections[self.shstrndx]
            for section in self.sections:
                section["name"] = self._string(base["offset"], base["size"], section["name_off"])

    def _string(self, offset: int, limit: int, position: int) -> str:
        if position >= limit or offset + position >= len(self.data):
            return ""
        end = self.data.find(b"\0", offset + position, offset + limit)
        if end < 0:
            end = min(offset + limit, len(self.data))
        return self.data[offset + position:end].decode("utf-8", "replace")

    def _read_symbols(self) -> None:
        """Names from the dynamic table and, when present, from the full symbol table."""
        self.symbols: set[str] = set()
        for section in self.sections:
            if section["type"] not in (SHT_DYNSYM, SHT_SYMTAB) or not section["entsize"]:
                continue
            if section["link"] >= len(self.sections):
                continue
            strings = self.sections[section["link"]]
            count = section["size"] // section["entsize"]
            for index in range(count):
                offset = section["offset"] + index * section["entsize"]
                try:
                    name_off = self._unpack("I", offset)[0]
                except ElfError:
                    break
                name = self._string(strings["offset"], strings["size"], name_off)
                if name:
                    self.symbols.add(name)

    def _read_dynamic(self) -> None:
        self.needed: list[str] = []
        self.rpath: list[str] = []
        self.bind_now = False
        for section in self.sections:
            if section["name"] != ".dynamic" and section["type"] != 6:
                continue
            count = section["size"] // (16 if self.elf_class == 64 else 8)
            for index in range(count):
                offset = section["offset"] + index * (16 if self.elf_class == 64 else 8)
                try:
                    if self.elf_class == 64:
                        tag, value = self._unpack("QQ", offset)
                    else:
                        tag, value = self._unpack("II", offset)
                except ElfError:
                    break
                if tag == DT_NEEDED:
                    self.needed.append(self._dynamic_string(value))
                elif tag in (DT_RPATH, DT_RUNPATH):
                    text = self._dynamic_string(value)
                    if text:
                        self.rpath.append(text)
                elif tag == DT_BIND_NOW or (tag == DT_FLAGS and value & DF_BIND_NOW) or \
                        (tag == DT_FLAGS_1 and value & DF_1_NOW):
                    self.bind_now = True

    def _dynamic_string(self, position: int) -> str:
        for section in self.sections:
            if section["type"] == SHT_STRTAB and section["name"] in (".dynstr", ".strtab"):
                return self._string(section["offset"], section["size"], position)
        return ""

    # ------------------------------------------------------------- properties

    @property
    def architecture(self) -> str:
        name = MACHINES.get(self.machine, f"machine {self.machine}")
        return f"{name}-{self.elf_class}"

    @property
    def type_name(self) -> str:
        return FILE_TYPE.get(self.file_type, f"type {self.file_type}")

    @property
    def executable(self) -> bool:
        return self.file_type in (2, 3) and bool(self.segments)

    @property
    def pie(self) -> bool:
        """Position independent: ET_DYN with an interpreter. ET_EXEC means fixed addresses."""
        return self.file_type == 3 and self.interpreter != ""

    @property
    def interpreter(self) -> str:
        for segment in self.segments:
            if segment["type"] == PT_INTERP:
                try:
                    return self._string(segment["offset"], segment["offset"] + 512, 0)
                except ElfError:
                    return ""
        return ""

    @property
    def nx(self) -> bool | None:
        """True = non-executable stack. None = the toolchain did not say."""
        for segment in self.segments:
            if segment["type"] == PT_GNU_STACK:
                return not bool(segment["flags"] & PF_X)
        return None

    @property
    def relro(self) -> str:
        if not any(segment["type"] == PT_GNU_RELRO for segment in self.segments):
            return "none"
        return "full" if self.bind_now else "partial"

    @property
    def canary(self) -> bool:
        return any(name.startswith("__stack_chk") for name in self.symbols)

    @property
    def fortify(self) -> bool:
        return any(name.endswith("_chk") for name in self.symbols)

    def has_symbol(self, *names: str) -> bool:
        return any(name in self.symbols for name in names)

    def strings(self, minimum: int = 5) -> set[str]:
        """Printable strings, like `strings` but in-house: one scan, not a loop per byte."""
        pattern = _string_pattern(minimum)
        return {piece.decode("ascii", "replace") for piece in pattern.findall(self.data)}

    def __repr__(self) -> str:
        return f"<Elf {self.path.name} {self.architecture} {self.type_name}>"


def is_elf(path: str | Path) -> bool:
    """True if the file is an ELF (including QNX compressed ones)."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(8)
    except OSError:
        return False
    return head.startswith(MAGIC) or head.startswith(QNX_COMPRESSED_MAGIC)


def is_qnx_compressed(path: str | Path) -> bool:
    """True if this is a compressed QNX ELF (QNX firmware compresses binaries this way)."""
    try:
        with open(path, "rb") as handle:
            return handle.read(8).startswith(QNX_COMPRESSED_MAGIC)
    except OSError:
        return False
