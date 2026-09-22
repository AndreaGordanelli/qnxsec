"""The command line, exercised end to end."""
from __future__ import annotations

import json

from qnxsec import cli


def test_file_command(bare_binary, capsys):
    assert cli.main(["file", bare_binary]) == 0
    output = capsys.readouterr().out
    assert "bare" in output
    assert "canary" in output


def test_file_command_json(bare_binary, capsys):
    assert cli.main(["file", bare_binary, "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["file_type"] == "elf"
    assert data["protections"]["canary"] is False


def test_firmware_command(tree, capsys):
    assert cli.main(["firmware", tree]) == 0
    output = capsys.readouterr().out
    assert "SIGNALS" in output
    assert "privileged" in output


def test_firmware_command_json_without_cards(tree, capsys):
    assert cli.main(["firmware", tree, "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert "summary" in data
    assert "cards" not in data


def test_firmware_command_json_with_cards(tree, capsys):
    assert cli.main(["firmware", tree, "--json", "--details"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["cards"]


def test_no_command_exits():
    from pytest import raises
    with raises(SystemExit):
        cli.main([])
