"""Build IFS images for the tests.

Written from the documented layout (QNX image.h), independently of the parser: if the
parser and this builder disagree about an offset, the tests fail.
"""
from __future__ import annotations

import struct

S_IFREG, S_IFDIR, S_IFLNK, S_IFCHR = 0o100000, 0o040000, 0o120000, 0o020000
ATTR = 24
HEADER_FIXED = 88


class IfsBuilder:
    """Assembles a valid IFS image in memory."""

    def __init__(self, mountpoint: str = "/", chain_paddr: int = 0, big_endian: bool = False):
        self.mountpoint = mountpoint
        self.chain_paddr = chain_paddr
        self.big_endian = big_endian
        self.entries: list[dict] = []
        self._next_ino = 1
        self.boot_ino: list[int] = []
        self.script_ino: int = 0

    # ------------------------------------------------------------------ add

    def _ino(self) -> int:
        ino = self._next_ino
        self._next_ino += 1
        return ino

    def add_file(self, path: str, data: bytes, mode: int = 0o644, uid: int = 0, gid: int = 0,
                 ino: int | None = None) -> int:
        ino = ino or self._ino()
        self.entries.append({"kind": "file", "path": path.lstrip("/"), "ino": ino,
                             "mode": S_IFREG | mode, "uid": uid, "gid": gid, "data": data,
                             "mtime": 0})
        return ino

    def add_dir(self, path: str, mode: int = 0o755, uid: int = 0, gid: int = 0,
                ino: int | None = None) -> int:
        ino = ino or self._ino()
        self.entries.append({"kind": "dir", "path": path.lstrip("/"), "ino": ino,
                             "mode": S_IFDIR | mode, "uid": uid, "gid": gid, "data": b"",
                             "mtime": 0})
        return ino

    def add_symlink(self, path: str, target: str, mode: int = 0o777, uid: int = 0,
                    gid: int = 0, ino: int | None = None) -> int:
        ino = ino or self._ino()
        self.entries.append({"kind": "symlink", "path": path.lstrip("/"), "ino": ino,
                             "mode": S_IFLNK | mode, "uid": uid, "gid": gid,
                             "target": target, "data": b"", "mtime": 0})
        return ino

    def add_device(self, path: str, dev: int = 1, rdev: int = 0, mode: int = 0o600,
                   uid: int = 0, gid: int = 0, ino: int | None = None) -> int:
        ino = ino or self._ino()
        self.entries.append({"kind": "device", "path": path.lstrip("/"), "ino": ino,
                             "mode": S_IFCHR | mode, "uid": uid, "gid": gid, "dev": dev,
                             "rdev": rdev, "data": b"", "mtime": 0})
        return ino

    # ---------------------------------------------------------------- build

    def _dirent(self, entry: dict, payload_offset: int) -> bytes:
        order = ">" if self.big_endian else "<"
        path = entry["path"].encode() + b"\0"
        kind = entry["kind"]
        if kind == "file":
            body = struct.pack(order + "II", payload_offset, len(entry["data"])) + path
        elif kind == "dir":
            body = path
        elif kind == "symlink":
            target = entry["target"].encode() + b"\0"
            body = struct.pack(order + "HH", ATTR + 4 + len(path), len(target)) + path + target
        else:
            body = struct.pack(order + "II", entry.get("dev", 0), entry.get("rdev", 0)) + path
        size = ATTR + len(body)
        padding = (-size) % 4
        head = struct.pack(order + "HHIIIII", size + padding, 0, entry["ino"], entry["mode"],
                           entry["gid"], entry["uid"], entry["mtime"])
        return head + body + b"\0" * padding

    def build(self) -> bytes:
        mountpoint = self.mountpoint.encode() + b"\0"
        dir_offset = HEADER_FIXED + len(mountpoint)
        dir_offset += (-dir_offset) % 4

        dirents = [self._dirent(entry, 0) for entry in self.entries]
        dirent_size = sum(len(chunk) for chunk in dirents)
        payload_start = dir_offset + dirent_size
        payload_start += (-payload_start) % 4

        payloads, offsets, cursor = [], [], payload_start
        for entry in self.entries:
            offsets.append(cursor)
            if entry["kind"] == "file":
                payloads.append(entry["data"])
                cursor += len(entry["data"])
                cursor += (-cursor) % 4
            else:
                payloads.append(b"")
        dirents = [self._dirent(entry, offset)
                   for entry, offset in zip(self.entries, offsets)]

        body = b"".join(dirents)
        image_size = payload_start + sum(len(chunk) for chunk in payloads)
        boot = list(self.boot_ino) + [0] * (4 - len(self.boot_ino))

        if self.big_endian:
            order = ">"
            signature = b"sfegami"
        else:
            order = "<"
            signature = b"imagefs"
        header = signature + b"\0" + struct.pack(
            order + "IIIIIIIIIIIIIIIIIIII", image_size, dir_offset + len(body), dir_offset,
            *boot, self.script_ino, self.chain_paddr, *([0] * 10), 0)
        header += mountpoint
        header += b"\0" * ((-len(header)) % 4)
        assert len(header) == dir_offset, (len(header), dir_offset)

        trailer = struct.pack(order + "I", 0)
        return header + body + b"\0" * (payload_start - dir_offset - len(body)) \
            + b"".join(payloads) + trailer

    # ------------------------------------------------------------- shortcuts

    def with_boot(self, inos: list[int]) -> "IfsBuilder":
        self.boot_ino = inos
        return self

    def with_script(self, ino: int) -> "IfsBuilder":
        self.script_ino = ino
        return self


def small_image(script_text: str = "") -> bytes:
    """A representative image: files, a directory, a symlink, a device, a setuid binary."""
    builder = IfsBuilder(mountpoint="/")
    builder.add_dir("bin")
    builder.add_dir("etc")
    builder.add_file("bin/hello", b"\x7fELF" + b"\0" * 60, mode=0o755)
    builder.add_file("bin/suid-tool", b"\x7fELF" + b"\0" * 60, mode=0o4755, uid=0, gid=0)
    builder.add_file("etc/config.conf", b"key = value\n", mode=0o644)
    builder.add_symlink("bin/link", "hello")
    builder.add_device("dev/console", dev=1, rdev=2)
    ino = builder.add_file("proc/boot/.script", (script_text or "#!/bin/sh\n").encode())
    builder.with_script(ino)
    return builder.build()
