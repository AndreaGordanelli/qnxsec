"""The boot script and buildfile reader: blocks, commands, entries, flags."""
from __future__ import annotations

import pytest

from qnxsec import bootscript

SCRIPT = """# comment
[virtual=armle-v7,raw +compress] .bootstrap = {
    startup-armle-v7 -a
    PATH=/proc/boot:/bin:/usr/bin
    procnto-smp-instr
}

[+script] .script = {
    display_msg "Starting QNX"
    waitfor /dev/ser1,10
    devc-ser8250 -u1 0x3f8,4
    chmod 777 /dev/shmem
    telnetd
    io-pkt-v6-hc -d e1000 &
    on -T tcpip ifconfig en0 10.0.0.2 up
    mount -uw /
}

[type=link] /bin/sh=/proc/boot/ksh
[perms=4755 uid=0 gid=0] /bin/passwd=passwd
[perms=0644] /etc/rc.local=rc.local
"""


def test_blocks_and_entries():
    build = bootscript.parse(SCRIPT)
    names = [block.name for block in build.blocks]
    assert ".bootstrap" in names and ".script" in names
    paths = {entry.path: entry for entry in build.entries}
    assert paths["/bin/sh"].source == "/proc/boot/ksh"
    assert paths["/bin/passwd"].mode == 0o4755
    assert paths["/bin/passwd"].uid == 0
    assert paths["/etc/rc.local"].mode == 0o644


def test_environment_and_commands():
    build = bootscript.parse(SCRIPT)
    assert build.environment["PATH"] == "/proc/boot:/bin:/usr/bin"
    programs = [command.program for command in build.commands]
    assert "devc-ser8250" in programs
    assert "procnto-smp-instr" in programs
    background = [command for command in build.commands if command.background]
    assert any(command.program == "io-pkt-v6-hc" for command in background)


def test_on_context():
    build = bootscript.parse(SCRIPT)
    in_context = [command for command in build.commands if command.context == "tcpip"]
    assert in_context and in_context[0].program == "ifconfig"


def test_waits_are_collected():
    build = bootscript.parse(SCRIPT)
    assert any("/dev/ser1" in waited for waited in build.waits)


def test_flags_world_writable_and_exposed_service():
    build = bootscript.parse(SCRIPT)
    kinds = {flag["kind"] for flag in build.flags}
    assert "world-writable" in kinds          # chmod 777 /dev/shmem
    assert "service-exposed" in kinds         # telnetd started at boot
    assert "root-remounted" in kinds          # mount -uw /


def test_missing_waitfor_is_flagged():
    text = "[+script] .script = {\n    io-pkt-v6-hc -d /dev/foo\n    ifconfig en0 up\n}\n"
    build = bootscript.parse(text)
    assert any(flag["kind"] == "no-waitfor" for flag in build.flags)


def test_setuid_entry_is_visible_in_the_report():
    parsed = bootscript.parse(SCRIPT)
    rendered = bootscript.report(parsed)
    assert "SIGNALS" in rendered
    assert "/bin/passwd" in rendered


def test_credentials_in_script_are_flagged():
    text = "[+script] .script = {\n    LOGIN_PASSWORD=superuser\n}\n"
    build = bootscript.parse(text)
    assert any(flag["kind"] == "credentials-in-script" for flag in build.flags)


def test_empty_script_is_rejected():
    with pytest.raises(bootscript.ScriptError):
        bootscript.parse("   \n# nothing\n")


def test_script_from_an_image_entry():
    from tests.support.ifs_builder import IfsBuilder

    builder = IfsBuilder()
    ino = builder.add_file("proc/boot/.script", SCRIPT.encode())
    builder.with_script(ino)
    image = __import__("qnxsec.ifs", fromlist=["open_image"]).open_image(builder.build())
    build = bootscript.from_entry(image.script(), image.read(image.script()))
    assert build.commands
    assert build.environment["PATH"].startswith("/proc/boot")
