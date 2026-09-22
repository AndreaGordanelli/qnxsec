"""Walking a tree: counts, privileges, targets, exclusions."""
from __future__ import annotations

from qnxsec import firmware, report


def test_full_scan(tree):
    result = firmware.analyse(tree)
    summary = result["summary"]

    assert summary["elf"] >= 3                       # hardened, bare, privileged
    assert summary["compressed"] == 1                # the fake compressed QNX ELF
    assert summary["architectures"]
    assert summary["protections"]["count"] == summary["elf"]

    # the file with the setuid bit must show up among the privileged ones
    assert any("privileged" in item for item in summary["privileged"])
    # and among the targets, because it is setuid and unprotected
    assert any("privileged" in item for item in summary["targets"])


def test_excluding_a_folder(tree):
    with_bin = firmware.analyse(tree)["summary"]
    without_bin = firmware.analyse(tree, exclude=("bin",))["summary"]
    assert without_bin["elf"] < with_bin["elf"]


def test_readable_summary(tree):
    text = report.summary_text(firmware.analyse(tree)["summary"])
    assert "SIGNALS" in text
    assert "targets to look at" in text


def test_readable_card(bare_binary):
    from qnxsec import checks
    text = report.card_text(checks.card(bare_binary, mode=0o4755))
    assert "canary no" in text
    assert "setuid" in text
    assert "worth a look" in text


def test_json_is_serialisable(tree):
    import json
    result = firmware.analyse(tree)
    reloaded = json.loads(report.to_json({"summary": result["summary"]}))
    assert reloaded["summary"]["elf"] == result["summary"]["elf"]
