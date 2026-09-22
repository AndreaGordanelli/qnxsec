"""La riga di comando, provata end-to-end."""
from __future__ import annotations

import json

from qnxsec import cli


def test_comando_file(binario_nudo, capsys):
    assert cli.main(["file", binario_nudo]) == 0
    uscita = capsys.readouterr().out
    assert "nudo" in uscita
    assert "canary" in uscita


def test_comando_file_json(binario_nudo, capsys):
    assert cli.main(["file", binario_nudo, "--json"]) == 0
    dati = json.loads(capsys.readouterr().out)
    assert dati["tipo_file"] == "elf"
    assert dati["protezioni"]["canary"] is False


def test_comando_firmware(albero, capsys):
    assert cli.main(["firmware", albero]) == 0
    uscita = capsys.readouterr().out
    assert "SINTESI" in uscita
    assert "conprivilegi" in uscita


def test_comando_firmware_json_senza_schede(albero, capsys):
    assert cli.main(["firmware", albero, "--json"]) == 0
    dati = json.loads(capsys.readouterr().out)
    assert "riassunto" in dati
    assert "schede" not in dati


def test_comando_firmware_json_con_schede(albero, capsys):
    assert cli.main(["firmware", albero, "--json", "--schede"]) == 0
    dati = json.loads(capsys.readouterr().out)
    assert dati["schede"]


def test_comando_sconosciuto_non_esplode():
    from pytest import raises
    with raises(SystemExit):
        cli.main([])
