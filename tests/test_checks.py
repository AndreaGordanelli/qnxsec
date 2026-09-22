"""I controlli: protezioni, superficie QNX, privilegi, punteggio."""
from __future__ import annotations

from qnxsec import checks


def test_scheda_di_un_binario(binario_protetto):
    scheda = checks.scheda(binario_protetto)
    assert scheda["tipo_file"] == "elf"
    assert scheda["qnx"] is True                      # ha resmgr_attach e MsgReceive
    assert scheda["protezioni"]["canary"] is True
    assert scheda["protezioni_assenti"] == []
    etichette = [voce["etichetta"] for voce in scheda["superficie"]]
    assert any("resource manager" in etichetta for etichetta in etichette)
    assert "strcpy" in scheda["funzioni_insidiose"]


def test_indizi_nelle_stringhe(binario_protetto):
    scheda = checks.scheda(binario_protetto)
    etichette = [voce["etichetta"] for voce in scheda["indizi"]]
    assert any("PPS" in etichetta for etichetta in etichette)
    assert any("configurazione" in etichetta for etichetta in etichette)
    assert any("segreto" in etichetta for etichetta in etichette)


def test_setuid_alza_il_punteggio(binario_nudo):
    senza = checks.scheda(binario_nudo, modo=0o755)
    con = checks.scheda(binario_nudo, modo=0o4755)
    assert senza["setuid"] is False and con["setuid"] is True
    assert con["punteggio"] > senza["punteggio"]
    assert con["bersaglio"] is True


def test_senza_stringhe_non_si_ferma(binario_protetto):
    scheda = checks.scheda(binario_protetto, stringhe=False)
    assert scheda["indizi"] == []
    assert scheda["tipo_file"] == "elf"


def test_file_compresso_qnx(tmp_path):
    compresso = tmp_path / "compresso"
    compresso.write_bytes(b"iwlyfmbp" + b"\0" * 64)
    scheda = checks.scheda(compresso)
    assert scheda["tipo_file"] == "elf-compresso-qnx"
    assert "scompattato" in scheda["nota"]


def test_file_qualunque(tmp_path):
    testo = tmp_path / "note.txt"
    testo.write_text("ciao\n")
    assert checks.scheda(testo)["tipo_file"] == "non-elf"


def test_binario_troncato_non_esplode(tmp_path, binario_nudo):
    tronco = tmp_path / "tronco"
    tronco.write_bytes(open(binario_nudo, "rb").read()[:120])
    scheda = checks.scheda(tronco)
    assert scheda["tipo_file"] in ("elf-illeggibile", "elf")


def test_mancanti_ordine_di_peso(binario_nudo):
    from qnxsec.elf import Elfo
    assenti = checks.mancanti(Elfo(binario_nudo))
    assert "canary" in assenti and "NX" in assenti
    assert assenti.index("canary") < assenti.index("PIE")
