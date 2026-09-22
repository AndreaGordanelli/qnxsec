"""QNX image filesystem (IFS) reader and extractor.

An IFS is the bootable filesystem QNX puts in flash: a header, a chain of directory
entries and the file payloads. Firmware dumps usually contain one or more of them,
sometimes at an offset inside a larger image, sometimes chained one after another.

Layout (little-endian, as documented in QNX's image.h):

    struct image_header {
        char     signature[7];      "imagefs"
        uint8    flags;
        uint32   image_size;        size from the header to the end of the trailer
        uint32   hdr_dir_size;      size from the header to the last dirent
        uint32   dir_offset;        offset from the header to the first dirent
        uint32   boot_ino[4];       inodes of the bootstrap programs
        uint32   script_ino;        inode of the startup script
        uint32   chain_paddr;       offset to the next filesystem signature
        uint32   spare[10];
        uint32   mountflags;
        char     mountpoint[];      NUL terminated
    };

    union image_dirent {
        struct image_attr {         common head, 24 bytes
            uint16 size;            size of this dirent, path included
            uint16 extattr_offset;
            uint32 ino;             zero means: skip this entry
            uint32 mode;
            uint32 gid;
            uint32 uid;
            uint32 mtime;
        };
        file    { attr; uint32 offset; uint32 size; char path[]; }
        dir     { attr; char path[]; }
        symlink { attr; uint16 sym_offset; uint16 sym_size; char path[]; char target[]; }
        device  { attr; uint32 dev; uint32 rdev; char path[]; }
    };

    struct image_trailer { uint32 cksum; };

Read-only, standard library only.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

SIGNATURE = b"imagefs"
SIGNATURE_REVERSED = b"sfegami"
HEADER_FIXED = 88               # up to and including mountflags
ATTR_SIZE = 24
TRAILER_SIZE = 4
DIRENT_FILE, DIRENT_DIR, DIRENT_SYMLINK, DIRENT_DEVICE = "file", "dir", "symlink", "device"

# mode bits
S_IFMT, S_IFREG, S_IFDIR, S_IFLNK = 0o170000, 0o100000, 0o040000, 0o120000


class ImageError(Exception):
    """The data is not a readable IFS image."""


@dataclass
class Entry:
    """One entry of the image filesystem."""
    path: str
    kind: str
    ino: int = 0
    mode: int = 0
    uid: int = 0
    gid: int = 0
    mtime: int = 0
    offset: int = 0
    size: int = 0
    target: str = ""
    dev: int = 0
    rdev: int = 0

    @property
    def permissions(self) -> str:
        return oct(self.mode & 0o7777)[2:].rjust(4, "0")

    @property
    def setuid(self) -> bool:
        return bool(self.mode & 0o4000)

    @property
    def setgid(self) -> bool:
        return bool(self.mode & 0o2000)

    @property
    def executable(self) -> bool:
        return bool(self.mode & 0o111)

    def as_dict(self) -> dict:
        return {"path": self.path, "kind": self.kind, "ino": self.ino,
                "mode": self.permissions, "uid": self.uid, "gid": self.gid,
                "size": self.size, "target": self.target,
                "setuid": self.setuid, "setgid": self.setgid}


@dataclass
class Image:
    """A parsed IFS image living inside a larger buffer."""
    data: bytes
    offset: int = 0                 # where the image starts inside `data`
    source: str = ""
    big_endian: bool = False
    image_size: int = 0
    hdr_dir_size: int = 0
    dir_offset: int = 0
    boot_ino: list[int] = field(default_factory=list)
    script_ino: int = 0
    chain_paddr: int = 0
    mountflags: int = 0
    mountpoint: str = ""
    entries: list[Entry] = field(default_factory=list)

    # ------------------------------------------------------------------ read

    def _u16(self, where: int) -> int:
        return struct.unpack_from(">H" if self.big_endian else "<H", self.data, where)[0]

    def _u32(self, where: int) -> int:
        return struct.unpack_from(">I" if self.big_endian else "<I", self.data, where)[0]

    def _text(self, where: int, limit: int) -> str:
        end = self.data.find(b"\0", where, where + limit)
        if end < 0:
            end = min(where + limit, len(self.data))
        return self.data[where:end].decode("utf-8", "replace")

    def _read_header(self) -> None:
        start = self.offset
        signature = self.data[start:start + 7]
        if signature == SIGNATURE:
            self.big_endian = False
        elif signature == SIGNATURE_REVERSED:
            self.big_endian = True
        else:
            raise ImageError("not an IFS image (no imagefs signature)")
        self.image_size = self._u32(start + 8)
        self.hdr_dir_size = self._u32(start + 12)
        self.dir_offset = self._u32(start + 16)
        self.boot_ino = [self._u32(start + 20 + 4 * index) for index in range(4)]
        self.script_ino = self._u32(start + 36)
        self.chain_paddr = self._u32(start + 40)
        self.mountflags = self._u32(start + 84)
        self.mountpoint = self._text(start + HEADER_FIXED, 256)
        if not (0 < self.dir_offset <= max(self.image_size, self.dir_offset)):
            raise ImageError("implausible dir_offset: not an IFS image")

    def _read_entries(self) -> None:
        where = self.offset + self.dir_offset
        end = self.offset + (self.hdr_dir_size or self.image_size or len(self.data))
        end = min(end, len(self.data))
        while where + ATTR_SIZE <= end:
            size = self._u16(where)
            if size < ATTR_SIZE:
                break
            entry = Entry(path="", kind="", ino=self._u32(where + 4), mode=self._u32(where + 8),
                          gid=self._u32(where + 12), uid=self._u32(where + 16),
                          mtime=self._u32(where + 20))
            body = where + ATTR_SIZE
            kind_bits = entry.mode & S_IFMT
            if kind_bits == S_IFREG:
                entry.kind = DIRENT_FILE
                entry.offset = self._u32(body)
                entry.size = self._u32(body + 4)
                entry.path = self._text(body + 8, size)
            elif kind_bits == S_IFDIR:
                entry.kind = DIRENT_DIR
                entry.path = self._text(body, size)
            elif kind_bits == S_IFLNK:
                entry.kind = DIRENT_SYMLINK
                sym_offset = self._u16(body)
                sym_size = self._u16(body + 2)
                entry.path = self._text(body + 4, size)
                if sym_size:
                    entry.target = self.data[where + sym_offset:where + sym_offset + sym_size] \
                        .decode("utf-8", "replace").rstrip("\0")
                else:
                    entry.target = self._text(body + 4 + len(entry.path) + 1, size)
            else:
                entry.kind = DIRENT_DEVICE
                entry.dev = self._u32(body)
                entry.rdev = self._u32(body + 4)
                entry.path = self._text(body + 8, size)
            if entry.ino and entry.path:
                self.entries.append(entry)
            where += size

    def parse(self) -> "Image":
        self._read_header()
        self._read_entries()
        return self

    # ------------------------------------------------------------- accessors

    @property
    def files(self) -> list[Entry]:
        return [entry for entry in self.entries if entry.kind == DIRENT_FILE]

    @property
    def directories(self) -> list[Entry]:
        return [entry for entry in self.entries if entry.kind == DIRENT_DIR]

    @property
    def symlinks(self) -> list[Entry]:
        return [entry for entry in self.entries if entry.kind == DIRENT_SYMLINK]

    @property
    def devices(self) -> list[Entry]:
        return [entry for entry in self.entries if entry.kind == DIRENT_DEVICE]

    def find(self, path: str) -> Entry | None:
        wanted = path.lstrip("/")
        for entry in self.entries:
            if entry.path == wanted:
                return entry
        return None

    def by_ino(self, ino: int) -> Entry | None:
        for entry in self.entries:
            if entry.ino == ino:
                return entry
        return None

    def read(self, entry: Entry) -> bytes:
        """Payload of a file entry."""
        if entry.kind != DIRENT_FILE:
            return b""
        start = self.offset + entry.offset
        return self.data[start:start + entry.size]

    def read_path(self, path: str) -> bytes:
        entry = self.find(path)
        return self.read(entry) if entry else b""

    def script(self) -> Entry | None:
        """The startup script entry, when the header points at one."""
        return self.by_ino(self.script_ino) if self.script_ino else None

    def boot_programs(self) -> list[Entry]:
        found = []
        for ino in self.boot_ino:
            entry = self.by_ino(ino) if ino else None
            if entry:
                found.append(entry)
        return found

    def next_image_offset(self) -> int | None:
        """Offset of the next filesystem in the chain, if the header declares one."""
        if not self.chain_paddr:
            return None
        return self.offset + self.chain_paddr

    def privileged(self) -> list[Entry]:
        """Entries carrying setuid or setgid bits: the ones worth looking at first."""
        return [entry for entry in self.entries if entry.setuid or entry.setgid]

    def summary(self) -> dict:
        kinds: dict[str, int] = {}
        for entry in self.entries:
            kinds[entry.kind] = kinds.get(entry.kind, 0) + 1
        script = self.script()
        return {
            "source": self.source,
            "offset": self.offset,
            "big_endian": self.big_endian,
            "image_size": self.image_size,
            "dir_offset": self.dir_offset,
            "entries": len(self.entries),
            "kinds": kinds,
            "mountpoint": self.mountpoint,
            "mountflags": self.mountflags,
            "chain_paddr": self.chain_paddr,
            "script": script.path if script else "",
            "boot_programs": [entry.path for entry in self.boot_programs()],
            "privileged": [entry.path for entry in self.privileged()],
        }

    # -------------------------------------------------------------- extract

    def extract(self, destination: str | Path, skip_devices: bool = True) -> dict:
        """Write the image to a directory, preserving modes, owners and symlinks.

        Returns a small report: how many entries were written and which ones were skipped.
        """
        destination = Path(destination)
        written, skipped, failed = [], [], []
        destination.mkdir(parents=True, exist_ok=True)
        for entry in sorted(self.entries, key=lambda item: item.path):
            target = destination / entry.path
            try:
                if entry.kind == DIRENT_DIR:
                    target.mkdir(parents=True, exist_ok=True)
                    written.append(entry.path)
                elif entry.kind == DIRENT_FILE:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(self.read(entry))
                    target.chmod(entry.mode & 0o7777)
                    written.append(entry.path)
                elif entry.kind == DIRENT_SYMLINK:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if target.exists() or target.is_symlink():
                        target.unlink()
                    target.symlink_to(entry.target or ".")
                    written.append(entry.path)
                elif skip_devices:
                    skipped.append(entry.path)
            except OSError as error:
                failed.append(f"{entry.path}: {error}")
        return {"destination": str(destination), "written": len(written),
                "skipped": skipped, "failed": failed}


# --------------------------------------------------------------------- helpers


def find_images(data: bytes, limit: int = 32) -> list[int]:
    """Offsets of every 'imagefs' signature in a buffer (both byte orders)."""
    offsets, start = [], 0
    while len(offsets) < limit:
        forward = data.find(SIGNATURE, start)
        backward = data.find(SIGNATURE_REVERSED, start)
        candidates = [position for position in (forward, backward) if position >= 0]
        if not candidates:
            break
        position = min(candidates)
        offsets.append(position)
        start = position + 1
    return offsets


def open_image(data: bytes, offset: int = 0, source: str = "") -> Image:
    """Parse the image starting at `offset`."""
    return Image(data=data, offset=offset, source=source).parse()


def images_in_file(path: str | Path, limit: int = 8) -> list[Image]:
    """Every IFS image found inside a file (a firmware dump, a raw flash read)."""
    path = Path(path)
    data = path.read_bytes()
    found = []
    for offset in find_images(data, limit=limit):
        try:
            found.append(open_image(data, offset, source=f"{path}@{offset:#x}"))
        except ImageError:
            continue
    return found


def follow_chain(image: Image, limit: int = 8) -> list[Image]:
    """Follow the chain of filesystems declared by the image header."""
    images, seen, current = [image], {image.offset}, image
    while len(images) < limit:
        following = current.next_image_offset()
        if following is None or following in seen or following >= len(current.data):
            break
        try:
            current = open_image(current.data, following, source=f"{image.source} chain")
        except ImageError:
            break
        seen.add(following)
        images.append(current)
    return images
