"""Compressed QNX ELF containers: header, block chain, honest refusals."""
from __future__ import annotations

import struct

import pytest

from qnxsec import deflate


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


def test_decompression_refuses_instead_of_guessing():
    container = deflate.parse(build_container([b"a" * 8]))
    with pytest.raises(deflate.DeflateError) as error:
        deflate.decompress(container, b"")
    assert "not implemented" in str(error.value)
