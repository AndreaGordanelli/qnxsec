"""Reading a QNX boot script and the buildfile it comes from.

The IFS carries a startup script (usually /proc/boot/.script) written in the same grammar
as the buildfile that produced the image:

    [virtual=armle-v7,raw +compress] .bootstrap = {
        startup-... -a
        PATH=/proc/boot:/bin:/usr/bin
        procnto-smp-instr
    }
    [+script] .script = {
        display_msg "Starting..."
        waitfor /dev/ser1,10
        devc-ser8250 -u1 0x3f8,4
        chmod 777 /dev/shmem
        io-pkt-v6-hc -d e1000 &
        on -T tcpip ifconfig en0 10.0.0.2
    }
    [type=link] /bin/sh=/proc/boot/ksh
    [perms=4755 uid=0 gid=0] /bin/passwd=passwd

This module extracts what the script actually starts, what it waits for and what it
loosens; the flags are the things a reviewer wants to see first, not a verdict.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import ifs

ATTRIBUTES = re.compile(r"^\s*\[([^\]]*)\]\s*(.*)$")
ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
BLOCK_START = re.compile(r"^([^\s=]+)\s*=\s*\{\s*$")
BLOCK_END = re.compile(r"^\s*\}\s*$")
DEVICE = re.compile(r"(/dev/[A-Za-z0-9_./-]+)")
PERMS = re.compile(r"perms\s*=\s*([0-7]{3,5})", re.I)
UID = re.compile(r"uid\s*=\s*(\d+)", re.I)

SERVICE_PREFIXES = ("devc-", "io-", "io-pkt", "procnto", "pci-", "dev-", "random",
                    "pipe", "mqueue", "slogger", "dumper", "inetd", "telnetd", "ftpd",
                    "sshd", "qconn", "photon", "screen", "service")


class ScriptError(Exception):
    """The text is not a readable buildfile or boot script."""


@dataclass
class Command:
    """One executable line of a script."""
    program: str
    arguments: list[str] = field(default_factory=list)
    line: str = ""
    background: bool = False
    context: str = ""                 # the argument of `on -T <name>`, when present
    attributes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"program": self.program, "arguments": self.arguments,
                "background": self.background, "context": self.context}


@dataclass
class Block:
    """A `[attributes] name = { ... }` section."""
    name: str
    attributes: list[str] = field(default_factory=list)
    lines: list[str] = field(default_factory=list)


@dataclass
class Entry:
    """A `[attributes] /path=source` line."""
    path: str
    source: str
    attributes: list[str] = field(default_factory=list)
    mode: int | None = None
    uid: int | None = None

    def as_dict(self) -> dict:
        return {"path": self.path, "source": self.source, "attributes": self.attributes,
                "mode": oct(self.mode) if self.mode is not None else None, "uid": self.uid}


@dataclass
class Buildfile:
    """A parsed buildfile: blocks, entries, commands, environment and flags."""
    blocks: list[Block] = field(default_factory=list)
    entries: list[Entry] = field(default_factory=list)
    commands: list[Command] = field(default_factory=list)
    environment: dict[str, str] = field(default_factory=dict)
    waits: list[str] = field(default_factory=list)
    flags: list[dict] = field(default_factory=list)

    @property
    def script_blocks(self) -> list[Block]:
        return [block for block in self.blocks
                if "script" in block.name or "script" in " ".join(block.attributes)]

    def summary(self) -> dict:
        return {
            "blocks": [{"name": block.name, "attributes": block.attributes,
                       "lines": len(block.lines)} for block in self.blocks],
            "entries": [entry.as_dict() for entry in self.entries],
            "commands": [command.as_dict() for command in self.commands],
            "environment": self.environment,
            "waits": self.waits,
            "flags": self.flags,
            "services": sorted({command.program for command in self.commands
                                if is_service(command.program)}),
        }


def is_service(program: str) -> bool:
    """Whether a program name looks like a QNX system service."""
    name = program.rsplit("/", 1)[-1]
    return name.startswith(SERVICE_PREFIXES) or name in {"inetd", "telnetd", "ftpd", "sshd",
                                                         "qconn", "dumper"}


def _add_flag(flags: list[dict], kind: str, detail: str, line: str = "") -> None:
    flags.append({"kind": kind, "detail": detail, "line": line.strip()[:160]})


def parse(text: str) -> Buildfile:
    """Parse a buildfile or a boot script."""
    if not any(line.strip() and not line.strip().startswith("#") for line in text.splitlines()):
        raise ScriptError("empty script")
    build = Buildfile()
    current: Block | None = None
    pending: list[str] = []

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        attributes: list[str] = []
        found = ATTRIBUTES.match(line)
        if found:
            attributes = [piece.strip() for piece in found.group(1).split(",") if piece.strip()]
            line = found.group(2).strip()
            if not line:
                pending = attributes
                continue

        if current is None:
            start = BLOCK_START.match(line)
            if start:
                current = Block(name=start.group(1), attributes=attributes or pending)
                pending = []
                continue
            if "=" in line and "/" in line.split("=", 1)[0]:
                path, _, source = line.partition("=")
                entry = Entry(path=path.strip(), source=source.strip(), attributes=attributes)
                perms = PERMS.search(" ".join(attributes))
                if perms:
                    entry.mode = int(perms.group(1), 8)
                who = UID.search(" ".join(attributes))
                if who:
                    entry.uid = int(who.group(1))
                build.entries.append(entry)
                continue
            if attributes:
                continue

        if current is not None:
            if BLOCK_END.match(line):
                build.blocks.append(current)
                current = None
                continue
            current.lines.append(line)
        else:
            build.blocks.append(Block(name=".script", attributes=["script"], lines=[line]))

    if current is not None:
        build.blocks.append(current)

    # the commands live in the script blocks, in order
    for block in build.blocks:
        context = ""
        for line in block.lines:
            assignment = ASSIGNMENT.match(line)
            if assignment and not line.startswith("/") and " " not in assignment.group(1):
                name, _, value = line.partition("=")
                build.environment[name.strip()] = value.strip().strip('"')
                if re.search(r"(password|passwd|secret|token|api_?key)", name, re.I):
                    _add_flag(build.flags, "credentials-in-script",
                              "a credential-looking assignment sits in the boot script", line)
                continue
            pieces = line.split()
            program = pieces[0]
            if program == "on":
                # `on -T name program args...`
                name = ""
                for index in range(1, len(pieces)):
                    if pieces[index] == "-T" and index + 1 < len(pieces):
                        name = pieces[index + 1]
                        break
                context = name
                tail = [piece for piece in pieces[1:] if piece not in ("-T", name)
                        and not piece.startswith("-")]
                if tail:
                    program = tail[0]
                    pieces = tail
                else:
                    continue
            if program in ("chmod", "chown", "mount", "reopen", "waitfor", "display_msg",
                           "rm", "ln", "sloginfo", "ifconfig", "route", "ioctl"):
                if program == "waitfor":
                    build.waits.extend(DEVICE.findall(line)
                                       or [pieces[1] if len(pieces) > 1 else ""])
                if program in ("chmod", "chown"):
                    for mode in re.findall(r"\b0?([0-7]{3,4})\b", line):
                        value = int(mode, 8)
                        if value & 0o007 and program == "chmod":
                            _add_flag(build.flags, "world-writable",
                                      f"mode {oct(value)} granted on {line.split()[-1]}", line)
                if program == "mount" and re.search(r"-uw|remount", line):
                    _add_flag(build.flags, "root-remounted",
                              "the root filesystem is remounted read-write", line)
                build.commands.append(Command(program=program, arguments=pieces[1:], line=line,
                                              background=line.endswith("&"), context=context))
                continue
            for device in DEVICE.findall(line):
                if not any(device in waited for waited in build.waits):
                    _add_flag(build.flags, "no-waitfor",
                              f"{device} is used but never waited for before this line", line)
            if any(word in line for word in ("telnetd", "ftpd", "sshd", "qconn", "-u root")):
                _add_flag(build.flags, "service-exposed",
                          "a login or debug service is started at boot", line)
            if re.search(r"(password|passwd|secret|token)\s*=", line, re.I):
                _add_flag(build.flags, "credentials-in-script",
                          "a credential-looking assignment sits in the boot script", line)
            build.commands.append(Command(program=program, arguments=pieces[1:], line=line,
                                          background=line.endswith("&"), context=context,
                                          attributes=block.attributes))
    return build


def from_entry(entry: ifs.Entry, data: bytes) -> Buildfile:
    """Parse the script stored in an IFS entry."""
    text = data.decode("utf-8", "replace")
    build = parse(text)
    return build


def report(build: Buildfile, limit: int = 40) -> str:
    """Short readable rendering of what the script does."""
    lines = ["Boot script", f"  blocks: {len(build.blocks)}"]
    for block in build.blocks:
        lines.append(f"    - {block.name} [{', '.join(block.attributes) or 'no attributes'}]"
                     f" · {len(block.lines)} lines")
    services = sorted({command.program for command in build.commands
                       if is_service(command.program)})
    if services:
        lines.append(f"  services started ({len(services)}): " + ", ".join(services[:12]))
    if build.environment:
        lines.append("  environment:")
        for name, value in sorted(build.environment.items())[:10]:
            lines.append(f"    - {name}={value}")
    if build.waits:
        lines.append("  waits for: " + ", ".join(sorted(set(build.waits))[:10]))
    if build.entries:
        lines.append(f"  image entries ({len(build.entries)}):")
        for entry in build.entries[:10]:
            extra = f" (mode {oct(entry.mode)})" if entry.mode is not None else ""
            lines.append(f"    - {entry.path} <- {entry.source}{extra}")
    lines.append("")
    lines.append("SIGNALS")
    if not build.flags:
        lines.append("  nothing worth a second look in the script")
    for flag in build.flags[:limit]:
        lines.append(f"  {flag['kind']}: {flag['detail']}")
        if flag["line"]:
            lines.append(f"      {flag['line']}")
    return "\n".join(lines)
