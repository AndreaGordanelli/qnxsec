"""The ELF reader: header, segments, symbols, protections."""
from __future__ import annotations

import pytest

from qnxsec import elf


def test_header(hardened_binary):
    binary = elf.Elf(hardened_binary)
    assert binary.architecture.endswith("64")
    assert binary.type_name == "DYN"          # PIE is ET_DYN with an interpreter
    assert binary.executable
    assert binary.pie


def test_protections_present(hardened_binary):
    binary = elf.Elf(hardened_binary)
    assert binary.canary is True
    assert binary.nx is True
    assert binary.relro == "full"


def test_protections_absent(bare_binary):
    binary = elf.Elf(bare_binary)
    assert binary.type_name == "EXEC"
    assert binary.pie is False
    assert binary.canary is False
    assert binary.nx is False
    assert binary.relro != "full"


def test_symbols_and_strings(hardened_binary):
    binary = elf.Elf(hardened_binary)
    assert binary.has_symbol("strcpy")
    assert binary.has_symbol("resmgr_attach")
    strings = binary.strings()
    assert any("/pps/system/test/object" in text for text in strings)


def test_not_an_elf(tmp_path):
    fake = tmp_path / "text.txt"
    fake.write_text("this is not an elf\n")
    with pytest.raises(elf.ElfError):
        elf.Elf(fake)
    assert elf.is_elf(fake) is False


def test_magic_detection(tmp_path, bare_binary):
    compressed = tmp_path / "compressed"
    compressed.write_bytes(b"iwlyfmbp" + b"\0" * 32)
    assert elf.is_qnx_compressed(compressed) is True
    assert elf.is_elf(compressed) is True
    assert elf.is_elf(bare_binary) is True
    assert elf.is_qnx_compressed(bare_binary) is False


def test_compressed_elf_is_not_parsed(tmp_path):
    compressed = tmp_path / "compressed"
    compressed.write_bytes(b"iwlyfmbp" + b"\0" * 32)
    with pytest.raises(elf.ElfError):
        elf.Elf(compressed)


def test_missing_file(tmp_path):
    with pytest.raises(OSError):
        elf.Elf(tmp_path / "does-not-exist")
