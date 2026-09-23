"""A compressed image is read through its chunk chain, not through a raw scan.

QNX stores the filesystem of a flash image as a chain of compressed chunks, each
preceded by a two byte big-endian length.  The signature inside such a file is
compressed, so a raw scan finds nothing at all: this was the shape of real
firmware that the reader could not open.
"""

from __future__ import annotations

import struct

import pytest

from qnxsec import ifs
from tests.support import lzo_reference, ucl_reference
from tests.support.ifs_builder import IfsBuilder

needs_lzo = pytest.mark.skipif(
    lzo_reference.path() is None,
    reason="no compiler or no liblzo2, the reference compressor cannot be built")
needs_ucl = pytest.mark.skipif(
    ucl_reference.path() is None,
    reason="no compiler or no libucl, the reference compressor cannot be built")

HEADER = 52


def startup_header(bits: int, startup_size: int, stored_size: int, imagefs_size: int) -> bytes:
    """A startup header as mkifs writes it in front of a compressed image."""
    header = bytearray(HEADER)
    struct.pack_into("<I", header, 0, ifs.STARTUP_SIGNATURE)
    header[6] = bits << 2
    struct.pack_into("<I", header, 32, startup_size)
    struct.pack_into("<I", header, 36, stored_size)
    struct.pack_into("<I", header, 44, imagefs_size)
    return bytes(header)


def chain(chunks: list[bytes]) -> bytes:
    """The chunk chain: length, payload, ... and a zero length to close it."""
    out = bytearray()
    for chunk in chunks:
        out += struct.pack(">H", len(chunk)) + chunk
    return bytes(out) + b"\x00\x00"


def inner_image() -> bytes:
    builder = IfsBuilder()
    builder.add_file("/bin/tool", b"\x7fELF" + bytes(64))
    builder.add_file("/etc/test.conf", b"key = value\n")
    return builder.build()


def test_the_startup_header_is_recognised():
    header = startup_header(3, HEADER, 564, 65280)
    info = ifs.startup_header(header + bytes(64), 0)
    assert info["compression"] == "ucl/nrv2b"
    assert info["startup_size"] == HEADER
    assert info["stored_size"] == 564


def test_the_first_four_bits_of_flags1_are_ignored():
    """NONE, ZLIB, LZO and UCL differ only in bits 2..4."""
    for bits, expected in ((0, "none"), (1, "zlib"), (2, "lzo"), (3, "ucl/nrv2b")):
        header = bytearray(startup_header(bits, HEADER, 0, 0))
        header[6] |= 0x03          # other flags in the low bits must not confuse it
        info = ifs.startup_header(bytes(header) + bytes(16), 0)
        assert info["compression"] == expected


def test_an_image_without_a_startup_header_has_none():
    assert ifs.startup_header(b"imagefs" + bytes(64), 0) is None


def test_an_algorithm_without_a_decoder_is_refused():
    with pytest.raises(ifs.ImageError):
        ifs.decompress_image(b"\x00\x00", 0, "zlib")


@needs_ucl
def test_a_ucl_compressed_image_is_read(tmp_path):
    payload = inner_image()
    body = startup_header(3, HEADER, 0, len(payload)) + chain(
        [ucl_reference.compress(payload, tmp_path)])
    image = ifs.open_image(body, 0, source="compressed")
    assert sorted(entry.path for entry in image.entries) == ["bin/tool", "etc/test.conf"]


@needs_lzo
def test_a_lzo_compressed_image_is_read(tmp_path):
    payload = inner_image()
    body = startup_header(2, HEADER, 0, len(payload)) + chain(
        [lzo_reference.compress(payload, tmp_path)])
    image = ifs.open_image(body, 0, source="compressed")
    assert len(image.entries) == 2


@needs_ucl
def test_several_chunks_are_joined(tmp_path):
    payload = inner_image()
    half = len(payload) // 2
    body = startup_header(3, HEADER, 0, len(payload)) + chain(
        [ucl_reference.compress(payload[:half], tmp_path),
         ucl_reference.compress(payload[half:], tmp_path)])
    assert ifs.decompress_image(body, HEADER, "ucl/nrv2b") == payload


@needs_ucl
def test_a_chunk_that_disagrees_with_its_length_is_refused(tmp_path):
    payload = inner_image()
    stream = ucl_reference.compress(payload, tmp_path)
    body = (startup_header(3, HEADER, 0, len(payload))
            + struct.pack(">H", len(stream) + 4) + stream + b"\x00\x00\x00\x00")
    with pytest.raises(ifs.ImageError):
        ifs.decompress_image(body, HEADER, "ucl/nrv2b")
