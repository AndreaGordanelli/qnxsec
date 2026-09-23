"""QNX compressed ELF containers ("iwlyfmbp").

QNX firmware usually stores binaries compressed: the file starts with the eight bytes
"iwlyfmbp", a small header and a chain of compressed blocks.

    0   8   magic "iwlyfmbp"
    8   4   uncompressed size (little endian)
    12  2   block size
    14  1   compression type: 0 = LZO1X, 1 = UCL/NRV2B
    15  1   spare

Each block then carries an eight-byte header:

    0   2   previous block's next value
    2   2   next: distance from this block to the following one (data follows)
    4   2   previous block's uncompressed size
    6   2   uncompressed size of this block

This module reads that structure: how big the file really is, how it is split and with
which algorithm, and it decompresses the payload with the decoders in
:mod:`qnxsec.lzo` and :mod:`qnxsec.ucl` -- both checked against the reference
libraries, not against themselves.  An algorithm without a verified decoder is
refused: a decompressor that quietly returns wrong bytes is worse than none.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from qnxsec import lzo, ucl

MAGIC = b"iwlyfmbp"
HEADER_SIZE = 16
BLOCK_HEADER_SIZE = 8
COMPRESSION = {0: "lzo1x", 1: "ucl/nrv2b"}


class DeflateError(Exception):
    """The data is not a readable compressed QNX ELF."""


@dataclass
class Block:
    """One compressed block."""
    index: int
    offset: int                  # distance of this block header from the file start
    previous_next: int
    next: int
    previous_size: int
    size: int                    # uncompressed size of this block
    data_offset: int
    data_size: int

    def as_dict(self) -> dict:
        return {"index": self.index, "offset": self.offset, "next": self.next,
                "size": self.size, "data_offset": self.data_offset,
                "data_size": self.data_size}


@dataclass
class Container:
    """A parsed iwlyfmbp file."""
    path: str = ""
    declared_size: int = 0
    block_size: int = 0
    compression: str = ""
    blocks: list[Block] = field(default_factory=list)
    total_uncompressed: int = 0
    total_compressed: int = 0

    @property
    def complete(self) -> bool:
        """Whether the blocks add up to the declared uncompressed size."""
        return self.total_uncompressed == self.declared_size

    @property
    def compression_ratio(self) -> float:
        if not self.total_uncompressed:
            return 0.0
        return round(self.total_compressed / self.total_uncompressed, 3)

    def as_dict(self) -> dict:
        return {"path": self.path, "declared_size": self.declared_size,
                "block_size": self.block_size, "compression": self.compression,
                "blocks": [block.as_dict() for block in self.blocks],
                "total_uncompressed": self.total_uncompressed,
                "total_compressed": self.total_compressed,
                "complete": self.complete, "ratio": self.compression_ratio}


def looks_like_container(path: str | Path) -> bool:
    """True when the file starts with the QNX compression magic."""
    try:
        with open(path, "rb") as handle:
            return handle.read(8) == MAGIC
    except OSError:
        return False


def parse(data: bytes, path: str = "") -> Container:
    """Read the container header and walk the block chain."""
    if len(data) < HEADER_SIZE or not data.startswith(MAGIC):
        raise DeflateError('not a QNX container (no "iwlyfmbp" magic)')
    declared, block_size, kind = struct.unpack_from("<IHB", data, 8)
    container = Container(path=path, declared_size=declared, block_size=block_size,
                          compression=COMPRESSION.get(kind, f"type {kind}"))

    # The chain is walked by following each block's "next" distance, and every block
    # also records the previous block's values; the parser stops when the declared
    # uncompressed size is covered or a link points outside the file.
    where = HEADER_SIZE
    seen = set()
    total = compressed = 0
    while where + BLOCK_HEADER_SIZE <= len(data) and where not in seen:
        seen.add(where)
        previous_next, next_hop, previous_size, size = struct.unpack_from("<HHHH", data, where)
        data_offset = where + BLOCK_HEADER_SIZE
        data_size = max(0, next_hop - BLOCK_HEADER_SIZE)
        if data_offset + data_size > len(data):
            data_size = max(0, len(data) - data_offset)
        container.blocks.append(Block(index=len(container.blocks), offset=where,
                                      previous_next=previous_next, next=next_hop,
                                      previous_size=previous_size, size=size,
                                      data_offset=data_offset, data_size=data_size))
        total += size
        compressed += data_size
        if declared and total >= declared:
            break
        if not next_hop:
            break
        where += next_hop

    container.total_uncompressed = total
    container.total_compressed = compressed
    return container


def parse_file(path: str | Path) -> Container:
    path = Path(path)
    return parse(path.read_bytes(), path=str(path))


def decompress(container: Container, data: bytes) -> bytes:
    """Decompress the payload, block by block.

    LZO1X and UCL/NRV2B are both implemented in this package and checked against
    streams from the reference libraries, so the bytes this returns can be
    trusted.  Anything else raises: a decompressor that returns wrong bytes
    silently is worse than one that refuses to try.

    ``data`` is the whole file, because the block map holds offsets into it.
    """
    decoders = {"lzo1x": lzo.decompress, "ucl/nrv2b": ucl.decompress}
    decoder = decoders.get(container.compression)
    if decoder is None:
        raise DeflateError(
            f"{container.compression or 'unknown'} payloads are not decompressed yet: "
            "only LZO1X and UCL/NRV2B are implemented and verified")

    payload = bytearray()
    for block in container.blocks:
        chunk = data[block.data_offset:block.data_offset + block.data_size]
        decoded, _ = decoder(chunk, expected_size=block.size)
        payload.extend(decoded)
    return bytes(payload)


def decompress_file(path: str | Path) -> bytes:
    """Read a container from disk and return its decompressed payload."""
    path = Path(path)
    data = path.read_bytes()
    return decompress(parse(data, path=str(path)), data)
