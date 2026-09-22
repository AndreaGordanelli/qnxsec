"""Pure Python LZO1X decompression.

QNX compresses image filesystem payloads with LZO1X: the same algorithm used
by the ``+compress`` attribute of ``mkifs`` and by the compressed QNX ELF
container.  Firmware images are almost never stored uncompressed, so a reader
that cannot decompress LZO sees nothing but noise.

The decoder follows the reference implementation (``lzo1x_d.ch``, LZO 2.10)
and is checked against streams produced by the real library: see
``tools/lzo_ref.c`` and ``tests/test_lzo.py``.

Nothing here executes what it reads.  The decoder writes into a fresh buffer,
refuses malformed input instead of guessing, and never trusts a length it was
not given.
"""

from __future__ import annotations

__all__ = ["LzoError", "decompress"]

M2_MAX_OFFSET = 0x0800
"""Largest offset that a two byte match can encode."""

M3_MAX_OFFSET = 0x4000
M4_MAX_OFFSET = 0xBFFF


class LzoError(ValueError):
    """Raised when a stream is truncated, malformed, or not LZO1X."""


def decompress(data: bytes, expected_size: int | None = None, offset: int = 0):
    """Decompress an LZO1X stream.

    Returns ``(payload, consumed)`` where ``consumed`` counts the input bytes
    that belong to the stream, so a caller can decompress a stream that sits
    inside a larger file.

    ``expected_size`` is the length the caller knows from the container; when
    given, a mismatch is an error rather than something to paper over.
    """
    if offset < 0 or offset >= len(data):
        raise LzoError("no stream at the requested offset")

    end = len(data)
    ip = offset
    out = bytearray()

    def byte() -> int:
        nonlocal ip
        if ip >= end:
            raise LzoError("stream ended in the middle of an instruction")
        value = data[ip]
        ip += 1
        return value

    def literals(count: int) -> None:
        nonlocal ip
        if count < 0 or ip + count > end:
            raise LzoError("stream ended in the middle of a literal run")
        out.extend(data[ip : ip + count])
        ip += count

    def match(m_pos: int, length: int) -> None:
        if m_pos < 0 or m_pos >= len(out):
            raise LzoError("match points outside the bytes decompressed so far")
        if m_pos + length <= len(out):
            out.extend(out[m_pos : m_pos + length])
        else:
            # Overlapping copy: the reference implementation copies byte by
            # byte and so must we, or a match would read bytes it has not
            # written yet.
            for index in range(length):
                out.append(out[m_pos + index])

    first = data[ip]
    state = "literal"
    t = first

    if first > 17:
        ip += 1
        t = first - 17
        if t < 4:
            state = "match_next"
        else:
            literals(t)
            t = byte()
            state = "match" if t >= 16 else "short_match"

    while True:
        if state == "literal":
            t = byte()
            if t >= 16:
                state = "match"
            else:
                if t == 0:
                    while data[ip] == 0:
                        t += 255
                        ip += 1
                        if ip >= end:
                            raise LzoError("stream ended in a literal length")
                    t += 15 + byte()
                literals(t + 3)
                # First literal run: a short match may follow directly.
                t = byte()
                state = "match" if t >= 16 else "short_match"

        elif state == "short_match":
            # Three byte match with the largest offset a short match can hold.
            m_pos = len(out) - (1 + M2_MAX_OFFSET) - (t >> 2) - (byte() << 2)
            match(m_pos, 3)
            state = "match_done"

        elif state == "match":
            if t >= 64:
                # M2: length 3..8, offset up to 0x0800 + 0x07ff.
                m_pos = len(out) - 1 - ((t >> 2) & 7) - (byte() << 3)
                length = (t >> 5) + 1
            elif t >= 32:
                # M3: length 3..33, offset up to 0x4000.
                length = t & 31
                if length == 0:
                    while data[ip] == 0:
                        length += 255
                        ip += 1
                        if ip >= end:
                            raise LzoError("stream ended in a match length")
                    length += 31 + byte()
                m_pos = len(out) - 1 - ((data[ip] >> 2) + (data[ip + 1] << 6))
                ip += 2
                length += 2
            elif t >= 16:
                # M4: length 3..9, offset up to 0xBFFF.  The end of the stream
                # is an M4 match whose offset is zero.
                m_pos = len(out) - ((t & 8) << 11)
                length = t & 7
                if length == 0:
                    while data[ip] == 0:
                        length += 255
                        ip += 1
                        if ip >= end:
                            raise LzoError("stream ended in a match length")
                    length += 7 + byte()
                m_pos -= (data[ip] >> 2) + (data[ip + 1] << 6)
                ip += 2
                if m_pos == len(out):
                    return _result(out, ip, expected_size)
                m_pos -= M3_MAX_OFFSET
                length += 2
            else:
                # M1: two byte match, offset up to 0x0400.
                m_pos = len(out) - 1 - (t >> 2) - (byte() << 2)
                match(m_pos, 2)
                state = "match_done"
                continue

            if m_pos < 0:
                raise LzoError("match points before the start of the stream")
            match(m_pos, length)
            state = "match_done"

        elif state == "match_done":
            # The two low bits of the match instruction tell how many literals
            # follow it before the next match.
            t = data[ip - 2] & 3
            state = "match_next" if t else "literal"

        else:  # match_next
            literals(t)
            t = byte()
            state = "match"


def _result(out: bytearray, ip: int, expected_size: int | None):
    if expected_size is not None and len(out) != expected_size:
        raise LzoError(
            "decompressed %d bytes, the container declared %d" % (len(out), expected_size)
        )
    return bytes(out), ip
