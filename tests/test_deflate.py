"""Compressed QNX ELF containers: header, block chain, honest refusals."""
from __future__ import annotations

import struct

import pytest

from qnxsec import deflate, lzo
from tests.support import lzo_reference, ucl_reference

needs_reference = pytest.mark.skipif(
    lzo_reference.path() is None,
    reason="no compiler or no liblzo2, the reference compressor cannot be built")

needs_ucl = pytest.mark.skipif(
    ucl_reference.path() is None,
    reason="no compiler or no libucl, the reference compressor cannot be built")


def build_container(chunks: list[bytes], block_size: int = 4096, kind: int = 1,
                    declared: int | None = None) -> bytes:
    """Assemble a container the way QNX does: header then a chain of blocks."""
    total = sum(len(chunk) for chunk in chunks)
    header = deflate.MAGIC + struct.pack("<IHB", declared or total, block_size, kind) + b"\0"
    out = bytearray(header)
    previous_next = 0
    previous_size = 0
    for chunk in chunks:
        following = deflate.BLOCK_HEADER_SIZE + len(chunk)
        out += struct.pack("<HHHH", previous_next, following, previous_size, len(chunk))
        out += chunk
        previous_next = following
        previous_size = len(chunk)
    return bytes(out)


def build_compressed_container(payloads: list[bytes], streams: list[bytes],
                               block_size: int = 4096, kind: int = 0) -> bytes:
    """A container whose blocks declare the uncompressed size and hold the stream."""
    total = sum(len(payload) for payload in payloads)
    out = bytearray(deflate.MAGIC + struct.pack("<IHB", total, block_size, kind) + b"\0")
    previous_next = 0
    previous_size = 0
    for payload, stream in zip(payloads, streams):
        following = deflate.BLOCK_HEADER_SIZE + len(stream)
        out += struct.pack("<HHHH", previous_next, following, previous_size, len(payload))
        out += stream
        previous_next = following
        previous_size = len(payload)
    return bytes(out)


def test_parse_container():
    data = build_container([b"a" * 100, b"b" * 50])
    container = deflate.parse(data, path="firmware/proc/boot/devc-ser8250")
    assert container.declared_size == 150
    assert container.block_size == 4096
    assert container.compression == "ucl/nrv2b"
    assert len(container.blocks) == 2
    assert [block.size for block in container.blocks] == [100, 50]
    assert container.total_uncompressed == 150
    assert container.total_compressed == 150
    assert container.complete is True
    assert container.compression_ratio == 1.0
    assert container.blocks[1].previous_size == 100


def test_compression_name_for_lzo():
    container = deflate.parse(build_container([b"x" * 10], kind=0))
    assert container.compression == "lzo1x"


def test_incomplete_container_is_reported():
    data = build_container([b"a" * 100], declared=500)
    container = deflate.parse(data)
    assert container.complete is False
    assert container.declared_size == 500


def test_truncated_block_data_is_clamped():
    data = build_container([b"a" * 100])
    container = deflate.parse(data[:-40])
    assert container.blocks
    assert container.blocks[0].data_size < 100          # clamped to what is really there


def test_parse_file_and_detection(tmp_path):
    path = tmp_path / "compressed"
    path.write_bytes(build_container([b"payload"]))
    assert deflate.looks_like_container(path) is True
    container = deflate.parse_file(path)
    assert container.path == str(path)
    assert container.blocks

    other = tmp_path / "plain"
    other.write_bytes(b"\x7fELF" + b"\0" * 32)
    assert deflate.looks_like_container(other) is False


def test_rejects_other_data():
    with pytest.raises(deflate.DeflateError):
        deflate.parse(b"\x7fELF" + b"\0" * 64)
    with pytest.raises(deflate.DeflateError):
        deflate.parse(b"short")


def test_ucl_blocks_are_decompressed(tmp_path):
    """The other QNX algorithm must round trip just as exactly."""
    payloads = [b"first block " * 60, bytes(range(256)) * 40, b"last"]
    streams = [ucl_reference.compress(payload, tmp_path) for payload in payloads]
    data = build_compressed_container(payloads, streams, kind=1)
    container = deflate.parse(data, path="firmware/proc/boot/compressed")
    assert container.compression == "ucl/nrv2b"
    assert container.complete is True
    assert deflate.decompress(container, data) == b"".join(payloads)


@needs_reference
def test_lzo_blocks_are_decompressed(tmp_path):
    """Blocks compressed by the reference library must come back byte for byte."""
    payloads = [b"first block " * 60, bytes(range(256)) * 40, b"last"]
    streams = [lzo_reference.compress(payload, tmp_path) for payload in payloads]
    data = build_compressed_container(payloads, streams)
    container = deflate.parse(data, path="firmware/proc/boot/compressed")
    assert container.compression == "lzo1x"
    assert container.complete is True
    assert deflate.decompress(container, data) == b"".join(payloads)


@needs_reference
def test_a_block_that_decodes_to_the_wrong_size_is_refused(tmp_path):
    """The declared block size is a check, not decoration."""
    payload = b"payload" * 100
    data = build_compressed_container([payload], [lzo_reference.compress(payload, tmp_path)])
    container = deflate.parse(data)
    container.blocks[0].size = 7        # a lie the decoder must catch
    with pytest.raises(lzo.LzoError):
        deflate.decompress(container, data)
