"""Il lettore ELF: intestazione, segmenti, simboli, protezioni."""
from __future__ import annotations

import pytest

from qnxsec import elf


def test_intestazione(binario_protetto):
    elfo = elf.Elfo(binario_protetto)
    assert elfo.architettura.endswith("64")
    assert elfo.tipo_nome == "DYN"          # PIE è ET_DYN con interprete
    assert elfo.eseguibile
    assert elfo.pie


def test_protezioni_presenti(binario_protetto):
    elfo = elf.Elfo(binario_protetto)
    assert elfo.canary is True
    assert elfo.nx is True
    assert elfo.relro == "completa"


def test_protezioni_assenti(binario_nudo):
    elfo = elf.Elfo(binario_nudo)
    assert elfo.tipo_nome == "EXEC"
    assert elfo.pie is False
    assert elfo.canary is False
    assert elfo.nx is False
    assert elfo.relro != "completa"


def test_simboli_e_stringhe(binario_protetto):
    elfo = elf.Elfo(binario_protetto)
    assert elfo.ha_simbolo("strcpy")
    assert elfo.ha_simbolo("resmgr_attach")
    stringhe = elfo.stringhe()
    assert any("/pps/system/prova/oggetto" in stringa for stringa in stringhe)


def test_non_elf(tmp_path):
    finto = tmp_path / "testo.txt"
    finto.write_text("non sono un elf\n")
    with pytest.raises(elf.ErroreElf):
        elf.Elfo(finto)
    assert elf.e_elf(finto) is False


def test_riconoscimento_magie(tmp_path, binario_nudo):
    compresso = tmp_path / "compresso"
    compresso.write_bytes(b"iwlyfmbp" + b"\0" * 32)
    assert elf.compr_elf_qnx(compresso) is True
    assert elf.e_elf(compresso) is True
    assert elf.e_elf(binario_nudo) is True
    assert elf.compr_elf_qnx(binario_nudo) is False


def test_elf_compresso_non_si_legge(tmp_path):
    compresso = tmp_path / "compresso"
    compresso.write_bytes(b"iwlyfmbp" + b"\0" * 32)
    with pytest.raises(elf.ErroreElf):
        elf.Elfo(compresso)


def test_file_inesistente(tmp_path):
    with pytest.raises(OSError):
        elf.Elfo(tmp_path / "nonesiste")
