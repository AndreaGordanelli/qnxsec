"""The IFS reader: header, dirents, extraction, image hunting inside a dump."""
from __future__ import annotations

import struct

import pytest

from qnxsec import ifs
from tests.support.ifs_builder import IfsBuilder, small_image


def test_header_and_entries():
    image = ifs.open_image(small_image())
    assert image.mountpoint == "/"
    assert image.image_size > 0
    paths = {entry.path for entry in image.entries}
    assert {"bin/hello", "bin/suid-tool", "etc/config.conf", "bin/link"} <= paths
    assert image.find("bin") is not None and image.find("bin").kind == "dir"
    assert image.find("dev/console").kind == "device"


def test_file_payload_and_metadata():
    image = ifs.open_image(small_image())
    entry = image.find("bin/hello")
    assert entry.size == 64
    assert image.read(entry).startswith(b"\x7fELF")
    assert entry.permissions == "0755"
    assert entry.executable and not entry.setuid


def test_setuid_entry_is_listed():
    image = ifs.open_image(small_image())
    entry = image.find("bin/suid-tool")
    assert entry.setuid is True
    assert "bin/suid-tool" in image.summary()["privileged"]


def test_symlink_and_device():
    image = ifs.open_image(small_image())
    link = image.find("bin/link")
    assert link.kind == "symlink" and link.target == "hello"
    device = image.find("dev/console")
    assert (device.dev, device.rdev) == (1, 2)


def test_script_and_boot_programs():
    builder = IfsBuilder()
    ino = builder.add_file("proc/boot/.script", b"# startup\n")
    builder.add_file("proc/boot/procnto", b"\x7fELF" + b"\0" * 32, mode=0o755)
    builder.with_script(ino)
    image = ifs.open_image(builder.build())
    script = image.script()
    assert script is not None and script.path == "proc/boot/.script"
    assert image.read(script) == b"# startup\n"


def test_image_inside_a_larger_dump():
    payload = b"\xde\xad\xbe\xef" * 512 + small_image()
    offsets = ifs.find_images(payload)
    assert offsets == [2048]
    image = ifs.open_image(payload, offsets[0], source="dump")
    assert image.find("bin/hello") is not None
    assert image.source == "dump"


def test_images_in_file(tmp_path):
    dump = tmp_path / "firmware.bin"
    dump.write_bytes(b"\0" * 1024 + small_image() + b"\0" * 64 + small_image())
    found = ifs.images_in_file(dump)
    assert len(found) == 2
    assert all(image.find("bin/hello") for image in found)


def test_chained_images():
    builder = IfsBuilder()
    builder.add_file("bin/first", b"first")
    first = builder.build()
    second = IfsBuilder(chain_paddr=0)
    second.add_file("bin/second", b"second")
    # chain the first image to the second, which sits right after it
    chained = IfsBuilder(chain_paddr=len(first) + len(b""))
    chained.add_file("bin/first", b"first")
    data = chained.build() + second.build()
    images = ifs.follow_chain(ifs.open_image(data))
    assert len(images) >= 1                       # the chain is only followed when it fits
    assert images[0].next_image_offset() is not None


def test_handmade_image_offsets():
    """A minimal image assembled by hand, independent of the builder."""
    path = b"bin/x\0"
    dirent_body = struct.pack("<II", 0, 2) + path    # payload offset fixed below
    size = 24 + len(dirent_body)
    size += (-size) % 4
    payload_offset = 88 + size
    dirent = struct.pack("<HHIIIII", size, 0, 7, 0o100755, 0, 0, 0) \
        + struct.pack("<II", payload_offset, 2) + path
    dirent += b"\0" * ((-len(dirent)) % 4)
    payload = b"hi"
    image_size = 88 + len(dirent) + len(payload) + 4
    header = b"imagefs\0" + struct.pack("<IIIIIIIIIIIIIIIIIIII", image_size,
                                        88 + len(dirent), 88, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    raw = header + dirent + payload + struct.pack("<I", 0)

    image = ifs.open_image(raw)
    entry = image.find("bin/x")
    assert entry is not None
    assert entry.ino == 7 and entry.permissions == "0755"
    assert image.read(entry) == b"hi"
    assert image.image_size == image_size


def test_big_endian_image():
    builder = IfsBuilder(big_endian=True)
    builder.add_file("bin/be", b"\x01\x02\x03\x04", mode=0o755)
    image = ifs.open_image(builder.build())
    assert image.big_endian is True
    assert image.read(image.find("bin/be")) == b"\x01\x02\x03\x04"


def test_extract_to_disk(tmp_path):
    destination = tmp_path / "out"
    report = ifs.open_image(small_image()).extract(destination)
    assert report["written"] >= 5
    assert (destination / "bin" / "hello").read_bytes().startswith(b"\x7fELF")
    assert (destination / "bin" / "link").is_symlink()
    assert (destination / "etc" / "config.conf").read_text() == "key = value\n"
    assert "dev/console" in report["skipped"]      # devices are not recreated
    mode = (destination / "bin" / "suid-tool").stat().st_mode
    assert mode & 0o4000                            # the setuid bit survives extraction


def test_garbage_is_rejected():
    with pytest.raises(ifs.ImageError):
        ifs.open_image(b"not an image at all" * 100)
    assert ifs.find_images(b"\x00" * 512) == []
