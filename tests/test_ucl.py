"""The NRV2B decoder is checked against streams from the real library.

``tools/ucl_ref.c`` compresses the same inputs with libucl, so a decoder bug
cannot hide behind a self-made encoder: the reference bytes come from the
implementation QNX itself links against.  Where no compiler or no libucl is
available the suite skips these tests instead of pretending they passed.
"""

from __future__ import annotations

import random

import pytest

from qnxsec.ucl import UclError, decompress
from tests.support import ucl_reference

needs_reference = pytest.mark.skipif(
    ucl_reference.path() is None,
    reason="no compiler or no libucl, the reference compressor cannot be built")


def samples() -> dict:
    """Inputs that exercise every branch: literals, long runs, matches, noise."""
    noise = random.Random(20260922)
    return {
        "single byte": b"A",
        "repeated byte": b"A" * 70000,
        "english text": b"the quick brown fox jumps over the lazy dog\n" * 900,
        "random bytes": bytes(noise.randrange(256) for _ in range(50000)),
        "few symbols": bytes(noise.randrange(4) for _ in range(60000)),
        "zeroes": bytes(120000),
        "source text": (ucl_reference.ROOT / "tools" / "ucl_ref.c").read_bytes() * 40,
    }


@needs_reference
@pytest.mark.parametrize("name", list(samples()))
def test_payload_survives_the_round_trip(tmp_path, name):
    payload = samples()[name]
    stream = ucl_reference.compress(payload, tmp_path)
    decoded, consumed = decompress(stream)
    assert decoded == payload
    assert consumed == len(stream)


@needs_reference
def test_stream_inside_a_larger_file(tmp_path):
    """A stream embedded in a container must decode from its own offset."""
    payload = bytes(range(256)) * 200
    stream = ucl_reference.compress(payload, tmp_path)
    embedded = b"container header" * 17 + stream + b"trailing bytes"
    decoded, consumed = decompress(embedded, offset=len(b"container header") * 17)
    assert decoded == payload
    assert consumed == len(b"container header") * 17 + len(stream)


@needs_reference
def test_declared_size_is_checked(tmp_path):
    stream = ucl_reference.compress(b"a payload long enough to compress" * 40, tmp_path)
    with pytest.raises(UclError):
        decompress(stream, expected_size=1)


def test_empty_input_is_refused():
    with pytest.raises(UclError):
        decompress(b"")


def test_all_zero_bits_are_refused():
    """A stream of zero bytes never terminates a match: it must fail, not spin."""
    with pytest.raises(UclError):
        decompress(bytes(40))
