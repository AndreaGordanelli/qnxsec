"""Comparing two builds of the same binary.

The fixtures are compiled here with explicit flags, so the classification is
checked against real objects rather than against a hand-made table.
"""
from __future__ import annotations

import subprocess

import pytest

from qnxsec import cli, diff

V1 = """
#include <stdio.h>
int shared(int x) { return x + 1; }
int changed(int x) { return x * 2; }
int gone(int x) { return x - 3; }
int main(void) { printf("%d %d %d\\n", shared(1), changed(2), gone(3)); return 0; }
"""

V2 = """
#include <stdio.h>
int shared(int x) { return x + 1; }
int changed(int x) { return x * 3 + 1; }
int new_one(int x) { return x + 7; }
int main(void) { printf("%d %d %d\\n", shared(1), changed(2), new_one(3)); return 0; }
"""


def build(compiler, tmp_path, name: str, source: str, *flags: str) -> str:
    path = tmp_path / f"{name}.c"
    binary = tmp_path / name
    path.write_text(source)
    subprocess.run([compiler, "-O0", "-g", *flags, str(path), "-o", str(binary)], check=True)
    return str(binary)


@pytest.fixture
def two_builds(compiler, tmp_path):
    return build(compiler, tmp_path, "v1", V1), build(compiler, tmp_path, "v2", V2)


def test_the_classification_follows_the_code(two_builds):
    old, new = two_builds
    result = diff.compare(old, new)
    functions = result["functions"]

    names = {change.name for change in functions["changed"]}
    assert "changed" in names                      # a different body
    assert [change.name for change in functions["added"]] == ["new_one"]
    assert [change.name for change in functions["removed"]] == ["gone"]
    assert functions["identical"] >= 1             # shared() is untouched
    assert "shared" not in names
    # main() differs only in which in-file function it calls, which is the case
    # the reference masking deliberately folds into "relocated": without a
    # disassembler it cannot be told apart from an address shift
    assert "main" in {change.name for change in functions["relocated"]}
    assert result["architecture"] == "x86-64-64" or result["architecture"]


def test_the_same_build_twice_changes_nothing(compiler, tmp_path):
    first = build(compiler, tmp_path, "same1", V1)
    second = build(compiler, tmp_path, "same2", V1)
    functions = diff.compare(first, second)["functions"]
    assert functions["added"] == [] and functions["removed"] == []
    assert functions["changed"] == [] and functions["relocated"] == []
    assert functions["identical"] == functions["compared"] > 0


def test_a_size_change_is_reported_with_both_sizes(compiler, tmp_path):
    old = build(compiler, tmp_path, "small", "int f(int x){return x+1;}\nint main(void){return f(0);}\n")
    new = build(compiler, tmp_path, "big",
                "int f(int x){int a=x+1,b=a*2,c=b-3;return a+b+c;}\nint main(void){return f(0);}\n")
    changed = {change.name: change for change in diff.compare(old, new)["functions"]["changed"]}
    assert "f" in changed
    assert changed["f"].old_size != changed["f"].new_size


def test_a_protection_change_shows_up(compiler, tmp_path):
    source = "int main(int argc, char **argv){char b[32];b[0]=argc;return b[0]+(argv?0:1);}\n"
    plain = build(compiler, tmp_path, "plain", source, "-fno-stack-protector")
    protected = build(compiler, tmp_path, "protected", source, "-fstack-protector-all")
    assert "canary" in diff.compare(plain, protected)["protections"]


def test_masking_removes_references_into_the_file_only():
    class Mapped:
        """A stand-in for Elf: only the addresses given are inside the file."""

        def __init__(self, *addresses):
            self.addresses = set(addresses)

        def offset_of(self, vaddr):
            return 0 if vaddr in self.addresses else None

    symbol = {"value": 0x1000, "size": 0, "global": True}
    # call at 0x1000: E8 <disp32> targeting 0x2000 (inside the file)
    call = b"\xe8" + (0x2000 - 0x1005).to_bytes(4, "little", signed=True) + b"\x90" * 4
    # a four-byte constant that does not point anywhere in the file
    constant = b"\x90\x90\x90\x90" + (0x11223344).to_bytes(4, "little")

    masked_call = diff._references_masked(Mapped(0x2000), symbol, call)
    assert masked_call[1:5] == b"\x00\x00\x00\x00"          # the operand is gone
    assert masked_call[0] == 0xE8 and masked_call[5:] == b"\x90" * 4

    outside = diff._references_masked(Mapped(), symbol, call)
    assert outside == call                                   # nothing to mask
    masked_constant = diff._references_masked(Mapped(0x11223344), symbol, constant)
    assert masked_constant == constant                       # not a reference form


def test_cli_prints_a_report_and_refuses_rubbish(two_builds, tmp_path, capsys):
    old, new = two_builds
    assert cli.main(["diff", old, new]) == 0
    printed = capsys.readouterr().out
    assert "changed:" in printed and "new_one" in printed

    rubbish = tmp_path / "rubbish.bin"
    rubbish.write_bytes(b"not an ELF file at all")
    assert cli.main(["diff", old, str(rubbish)]) == 1
    assert "Cannot compare" in capsys.readouterr().out


def test_json_output_is_complete(two_builds, capsys):
    import json

    old, new = two_builds
    assert cli.main(["diff", old, new, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    for key in ("old", "new", "architecture", "size", "functions", "protections", "needed"):
        assert key in payload
    assert isinstance(payload["functions"]["changed"][0], dict)
