"""Pure Python UCL/NRV2B decompression.

QNX marks image-level compression in the startup header and uses UCL (NRV2B) for
part of it -- ``mkifs`` writes type 0x0c for UCL.  A reader that cannot decode it
sees nothing of a compressed image.

The decoder follows the reference implementation (``ucl/n2b_d.c`` with the
``getbit_8`` reader from ``getbit.h``) and, like the LZO one, is checked against
streams produced by the real library: see ``tools/ucl_ref.c`` and
``tests/test_ucl.py``.
"""

from __future__ import annotations

__all__ = ["UclError", "decompress"]

MASK = 0xFFFFFFFF
"""The reference implementation works on 32-bit values throughout."""


class UclError(ValueError):
    """Raised when an NRV2B stream is truncated or malformed."""


def decompress(data: bytes, expected_size: int | None = None, offset: int = 0):
    """Decompress an NRV2B stream.

    Returns ``(payload, consumed)`` so a stream sitting inside a larger file can
    be decoded from its own offset.  ``expected_size``, when given, is enforced
    rather than papered over.
    """
    if offset < 0 or offset >= len(data):
        raise UclError("no stream at the requested offset")

    end = len(data)
    ilen = offset
    bb = 0
    last_m_off = 1
    out = bytearray()

    def getbit() -> int:
        """The getbit_8 reader: one bit at a time, most significant bit first."""
        nonlocal bb, ilen
        bb = (bb * 2) & MASK
        if bb & 0xFF:
            return (bb >> 8) & 1
        if ilen >= end:
            raise UclError("stream ended inside a bit run")
        bb = (data[ilen] * 2 + 1) & MASK
        ilen += 1
        return (bb >> 8) & 1

    while True:
        while getbit():
            if ilen >= end:
                raise UclError("stream ended inside a literal run")
            out.append(data[ilen])
            ilen += 1

        m_off = 1
        while True:
            m_off = m_off * 2 + getbit()
            if m_off > 0xFFFFFF + 3:
                raise UclError("match offset is out of range")
            if getbit():
                break
        if m_off == 2:
            m_off = last_m_off
        else:
            if ilen >= end:
                raise UclError("stream ended inside a match offset")
            m_off = (m_off - 3) * 256 + data[ilen]
            ilen += 1
            if m_off == MASK:
                break                       # the end-of-stream marker
            m_off += 1
            last_m_off = m_off

        m_len = getbit() * 2 + getbit()
        if m_len == 0:
            m_len += 1
            while True:
                m_len = m_len * 2 + getbit()
                if getbit():
                    break
            m_len += 2
        if m_off > 0xD00:
            m_len += 1

        if m_off > len(out):
            raise UclError("match points before the bytes decompressed so far")
        position = len(out) - m_off
        for index in range(m_len + 1):
            out.append(out[position + index])

    if expected_size is not None and len(out) != expected_size:
        raise UclError(
            "decompressed %d bytes, the container declared %d" % (len(out), expected_size))
    return bytes(out), ilen
