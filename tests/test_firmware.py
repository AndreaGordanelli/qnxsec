"""La scansione di un albero: conteggi, privilegi, bersagli, esclusioni."""
from __future__ import annotations

from qnxsec import firmware, report


def test_scansione_completa(albero):
    esito = firmware.analizza(albero)
    riassunto = esito["riassunto"]

    assert riassunto["elf"] >= 3                     # protetto, nudo, conprivilegi
    assert riassunto["compressi"] == 1               # il finto ELF compresso QNX
    assert "proc" not in riassunto["radice"]
    assert riassunto["architetture"]
    assert riassunto["protezioni"]["conta"] == riassunto["elf"]

    # il file con il bit setuid deve comparire fra i privilegiati
    assert any("conprivilegi" in voce for voce in riassunto["privilegiati"])
    # e deve finire fra i bersagli, perché è setuid e senza protezioni
    assert any("conprivilegi" in voce for voce in riassunto["bersagli"])


def test_esclusione_di_una_cartella(albero):
    con = firmware.analizza(albero)["riassunto"]
    senza = firmware.analizza(albero, escludi=("bin",))["riassunto"]
    assert senza["elf"] < con["elf"]


def test_riassunto_leggibile(albero):
    testo = report.riassunto_testo(firmware.analizza(albero)["riassunto"])
    assert "SINTESI" in testo
    assert "bersagli da guardare" in testo


def test_scheda_leggibile(binario_nudo):
    from qnxsec import checks
    testo = report.scheda_testo(checks.scheda(binario_nudo, modo=0o4755))
    assert "canary no" in testo
    assert "setuid" in testo
    assert "da guardare" in testo


def test_json_serializzabile(albero):
    import json
    esito = firmware.analizza(albero)
    riletto = json.loads(report.in_json({"riassunto": esito["riassunto"]}))
    assert riletto["riassunto"]["elf"] == esito["riassunto"]["elf"]
