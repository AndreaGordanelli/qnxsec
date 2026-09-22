"""Checks for a single binary: which protections are present, how much QNX surface it
exposes, and what its strings give away.

Two different questions:
  - how *exploitable* is this binary (canary, PIE, NX, RELRO, FORTIFY);
  - how much *surface* does it expose (resource manager, IPC channels, abilities, commands).

Nothing is executed: this only reads.
"""
from __future__ import annotations

from pathlib import Path

from .elf import Elf, ElfError, is_elf, is_qnx_compressed

# symbols that say "this process talks to the rest of the system"
QNX_SURFACE = {
    "resmgr_attach": "resource manager (publishes in /dev)",
    "name_attach": "named IPC channel",
    "message_attach": "message handler",
    "pulse_attach": "pulse handler",
    "MsgReceive": "receives messages",
    "MsgSend": "sends messages",
    "MsgReply": "replies to messages",
    "MsgDeliverEvent": "delivers events",
    "MsgReceivePulse": "receives pulses",
    "procmgr_ability": "process ability",
    "secpol": "security policy",
    "iofunc_": "resource library (iofunc)",
    "dispatch_": "message dispatch",
    "ThreadCtl": "thread control (privileged operations)",
    "shm_open": "shared memory",
    "mq_open": "POSIX message queues",
    "timer_create": "timer",
    "inotify": "file notifications",
}

# symbols that say "this process can change its privileges"
PRIVILEGE = {
    "setuid": "changes user",
    "seteuid": "changes effective user",
    "setresuid": "changes real/effective user",
    "setgid": "changes group",
    "setegid": "changes effective group",
    "setgroups": "changes groups",
    "chroot": "changes root",
    "sysctl": "kernel parameters",
    "chmod": "changes permissions",
    "fchmod": "changes permissions",
    "chown": "changes owner",
    "fchown": "changes owner",
}

# execution symbols and functions with a long history of trouble
EXECUTION = {
    "system": "runs shell commands",
    "popen": "runs shell commands",
    "execve": "runs programs",
    "execl": "runs programs",
    "execvp": "runs programs",
    "posix_spawn": "spawns processes",
    "spawn": "spawns processes",
    "dlopen": "loads libraries at runtime",
}
RISKY_FUNCTIONS = {"strcpy", "strcat", "sprintf", "gets", "mktemp", "alloca", "vsprintf", "scanf"}

# paths and words worth a second look: plain substrings, not regular expressions, because
# across a whole firmware the difference in speed is noticeable.
HINTS: list[tuple[tuple[str, ...], str, bool]] = [
    (("/pps/",), "PPS: published objects", False),
    (("/dev/shmem",), "shared memory in /dev/shmem", False),
    (("/dev/mem",), "direct physical memory access", False),
    (("/proc/boot",), "boot image", False),
    (("/dev/name",), "IPC namespace", False),
    (("/dev/io-",), "I/O drivers", False),
    (("LD_PRELOAD", "LD_LIBRARY_PATH"), "library loading variables", False),
    ((".conf",), "configuration file", False),
    (("password", "passwd", "secret", "api_key", "api-key", "token="),
     "keyword or secret", True),
    (("slog2", "/dev/slog"), "system log", False),
    (("pidin", "on -t", "/proc/"), "system commands and paths", True),
    (("debug", "dumper", "backdoor"), "debug hint", True),
]


def _symbols_in(elf: Elf, table: dict) -> list[dict]:
    found = []
    for key, label in table.items():
        if elf.has_symbol(key):
            found.append({"symbol": key, "label": label})
    return found


def is_qnx(elf: Elf) -> bool:
    """Whether this binary is QNX: from its symbols, its interpreter or its libraries."""
    if any(name.startswith(("Msg", "resmgr_", "iofunc_", "dispatch_", "procmgr_", "secpol"))
           for name in elf.symbols):
        return True
    if "qnx" in elf.interpreter.lower() or "procnto" in elf.interpreter.lower():
        return True
    return any("qnx" in name.lower() for name in elf.needed)


def protections(elf: Elf) -> dict:
    return {
        "canary": elf.canary,
        "nx": elf.nx,
        "pie": elf.pie,
        "relro": elf.relro,
        "fortify": elf.fortify,
    }


def missing_protections(elf: Elf) -> list[str]:
    """Missing protections, ordered by how much they matter to an attacker."""
    missing = []
    if not elf.canary:
        missing.append("canary")
    if not elf.pie and elf.executable:
        missing.append("PIE")
    if elf.nx is False:
        missing.append("NX")
    if elf.relro == "none":
        missing.append("RELRO")
    return missing


def string_hints(elf: Elf, limit: int = 25) -> list[dict]:
    found, seen = [], set()
    for text in elf.strings():
        lowered = text.lower()
        for words, label, case_insensitive in HINTS:
            if any(word in (lowered if case_insensitive else text) for word in words):
                key = (label, text[:120])
                if key not in seen:
                    seen.add(key)
                    found.append({"label": label, "string": text[:120]})
                break
    return found[:limit]


def card(path: str | Path, mode: int | None = None, strings: bool = True) -> dict:
    """Full card for one file: protections, surface, hints, score.

    `mode` is the file mode on the filesystem (to see setuid/setgid); without it the
    privilege bits stay unknown. `strings=False` skips string extraction, which is the
    slowest part on a very large binary.
    """
    path = Path(path)
    base = {"path": str(path), "name": path.name,
            "size": path.stat().st_size if path.exists() else 0}

    setuid = bool(mode is not None and mode & 0o4000)
    setgid = bool(mode is not None and mode & 0o2000)
    base["setuid"], base["setgid"] = setuid, setgid

    if is_qnx_compressed(path):
        base.update({"file_type": "qnx-compressed-elf", "note":
                     "compressed QNX ELF (iwlyfmbp): decompress it before analysing"})
        return base
    if not is_elf(path):
        base.update({"file_type": "not-elf"})
        return base

    try:
        elf = Elf(path)
    except ElfError as error:
        base.update({"file_type": "unreadable-elf", "note": str(error)})
        return base
    except OSError as error:
        base.update({"file_type": "error", "note": str(error)})
        return base

    surface = _symbols_in(elf, QNX_SURFACE)
    privilege = _symbols_in(elf, PRIVILEGE)
    execution = _symbols_in(elf, EXECUTION)
    risky = sorted(name for name in elf.symbols if name in RISKY_FUNCTIONS)
    found_protections = protections(elf)
    missing = missing_protections(elf)

    score = 0
    score += 3 if setuid else 0
    score += 2 if setgid else 0
    score += 2 * len([item for item in missing if item in ("canary", "NX")])
    score += 1 * len([item for item in missing if item in ("PIE", "RELRO")])
    score += 2 if execution else 0
    score += 1 if risky else 0
    score += 2 if surface else 0

    target = bool(surface or setuid) and bool({"canary", "PIE", "NX"} & set(missing))

    base.update({
        "file_type": "elf",
        "qnx": is_qnx(elf),
        "architecture": elf.architecture,
        "type": elf.type_name,
        "protections": found_protections,
        "missing_protections": missing,
        "surface": surface,
        "privilege": privilege,
        "execution": execution,
        "risky_functions": risky,
        "needed": sorted(elf.needed),
        "rpath": elf.rpath,
        "hints": string_hints(elf) if strings else [],
        "score": score,
        "target": target,
    })
    return base
