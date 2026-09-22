"""The checks: protections, QNX surface, privileges, score."""
from __future__ import annotations

from qnxsec import checks


def test_card_for_a_binary(hardened_binary):
    entry = checks.card(hardened_binary)
    assert entry["file_type"] == "elf"
    assert entry["qnx"] is True                        # it has resmgr_attach and MsgReceive
    assert entry["protections"]["canary"] is True
    assert entry["missing_protections"] == []
    labels = [item["label"] for item in entry["surface"]]
    assert any("resource manager" in label for label in labels)
    assert "strcpy" in entry["risky_functions"]


def test_string_hints(hardened_binary):
    entry = checks.card(hardened_binary)
    labels = [item["label"] for item in entry["hints"]]
    assert any("PPS" in label for label in labels)
    assert any("configuration" in label for label in labels)
    assert any("secret" in label for label in labels)


def test_setuid_raises_the_score(bare_binary):
    without = checks.card(bare_binary, mode=0o755)
    with_setuid = checks.card(bare_binary, mode=0o4755)
    assert without["setuid"] is False and with_setuid["setuid"] is True
    assert with_setuid["score"] > without["score"]
    assert with_setuid["target"] is True


def test_no_strings_still_works(hardened_binary):
    entry = checks.card(hardened_binary, strings=False)
    assert entry["hints"] == []
    assert entry["file_type"] == "elf"


def test_qnx_compressed_file(tmp_path):
    compressed = tmp_path / "compressed"
    compressed.write_bytes(b"iwlyfmbp" + b"\0" * 64)
    entry = checks.card(compressed)
    assert entry["file_type"] == "qnx-compressed-elf"
    assert "decompress" in entry["note"]


def test_plain_file(tmp_path):
    text = tmp_path / "notes.txt"
    text.write_text("hello\n")
    assert checks.card(text)["file_type"] == "not-elf"


def test_truncated_binary_does_not_explode(tmp_path, bare_binary):
    truncated = tmp_path / "truncated"
    truncated.write_bytes(open(bare_binary, "rb").read()[:120])
    entry = checks.card(truncated)
    assert entry["file_type"] in ("unreadable-elf", "elf")


def test_missing_protections_order_by_weight(bare_binary):
    from qnxsec.elf import Elf
    missing = checks.missing_protections(Elf(bare_binary))
    assert "canary" in missing and "NX" in missing
    assert missing.index("canary") < missing.index("PIE")
