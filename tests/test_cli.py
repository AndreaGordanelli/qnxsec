"""The command line, exercised end to end."""
from __future__ import annotations

import json

from qnxsec import cli
from tests.support.ifs_builder import IfsBuilder

SCRIPT = """[+script] .script = {
    display_msg "Starting"
    waitfor /dev/ser1,10
    devc-ser8250 -u1 0x3f8,4
    chmod 777 /dev/shmem
    telnetd
}
[perms=4755 uid=0 gid=0] /bin/passwd=passwd
"""


def image_bytes() -> bytes:
    builder = IfsBuilder()
    builder.add_dir("bin")
    builder.add_file("bin/hello", b"\x7fELF" + b"\0" * 64, mode=0o755)
    ino = builder.add_file("proc/boot/.script", SCRIPT.encode())
    builder.with_script(ino)
    return builder.build()


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


def test_ifs_command_lists_images(tmp_path, capsys):
    dump = tmp_path / "firmware.bin"
    dump.write_bytes(b"\0" * 2048 + image_bytes())
    assert cli.main(["ifs", str(dump)]) == 0
    output = capsys.readouterr().out
    assert "Image 1 at offset 0x800" in output
    assert "proc/boot/.script" in output
    assert "files (2)" in output


def test_ifs_command_extracts(tmp_path, capsys):
    dump = tmp_path / "firmware.bin"
    dump.write_bytes(image_bytes())
    target = tmp_path / "out"
    assert cli.main(["ifs", str(dump), "--extract", str(target)]) == 0
    assert (target / "image1" / "bin" / "hello").read_bytes().startswith(b"\x7fELF")
    assert "extracted" in capsys.readouterr().out


def test_ifs_command_without_image(tmp_path, capsys):
    plain = tmp_path / "nothing.bin"
    plain.write_bytes(b"\0" * 4096)
    assert cli.main(["ifs", str(plain)]) == 1
    assert "No IFS image" in capsys.readouterr().out


def test_bootscript_command(tmp_path, capsys):
    script = tmp_path / "buildfile"
    script.write_text(SCRIPT)
    assert cli.main(["bootscript", str(script)]) == 0
    output = capsys.readouterr().out
    assert "SIGNALS" in output
    assert "world-writable" in output
    assert "service-exposed" in output


def test_bootscript_command_json(tmp_path, capsys):
    script = tmp_path / "buildfile"
    script.write_text(SCRIPT)
    assert cli.main(["bootscript", str(script), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["commands"]
    assert any(flag["kind"] == "world-writable" for flag in data["flags"])


def test_bootscript_from_an_image(tmp_path, capsys):
    dump = tmp_path / "firmware.bin"
    dump.write_bytes(image_bytes())
    assert cli.main(["bootscript", str(dump)]) == 0
    assert "Boot script" in capsys.readouterr().out


def test_compressed_command(tmp_path, capsys):
    import struct

    payload = b"iwlyfmbp" + struct.pack("<IHB", 4096, 4096, 1) + b"\0"
    payload += struct.pack("<HHHH", 0, 8 + 64, 0, 64) + b"z" * 64
    path = tmp_path / "compressed-driver"
    path.write_bytes(payload)
    assert cli.main(["compressed", str(path)]) == 0
    output = capsys.readouterr().out
    assert "ucl/nrv2b" in output
    assert "1 blocks" in output


def test_surface_command_writes_graphs(tree, tmp_path, capsys):
    dot = tmp_path / "graph.dot"
    mermaid = tmp_path / "graph.mmd"
    assert cli.main(["surface", tree, "--dot", str(dot), "--mermaid", str(mermaid)]) == 0
    assert dot.read_text().startswith("digraph surface {")
    assert mermaid.read_text().startswith("graph LR")


def test_dump_command_over_a_firmware(tmp_path, capsys):
    dump = tmp_path / "firmware.bin"
    dump.write_bytes(b"\x00" * 512 + image_bytes())
    target = tmp_path / "unpacked"
    assert cli.main(["dump", str(dump), "--extract", str(target)]) == 0
    output = capsys.readouterr().out
    assert "Image 1 at offset" in output
    assert "Boot script" in output
    assert (target / "image1" / "bin" / "hello").exists()


def test_dump_command_json(tmp_path, capsys):
    dump = tmp_path / "firmware.bin"
    dump.write_bytes(image_bytes())
    assert cli.main(["dump", str(dump), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["images"][0]["summary"]["entries"] >= 3
    assert data["images"][0]["script"]["commands"]


def test_no_command_exits():
    from pytest import raises
    with raises(SystemExit):
        cli.main([])
