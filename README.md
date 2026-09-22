# qnxsec

Static analysis for QNX firmware and systems: what a binary is protected with, what
system surface it exposes, and which binaries are worth looking at first.

Written from scratch, standard library only, read-only. It never executes what it
analyses and never needs a QNX toolchain to run.

## Why

QNX tooling has a long history of good research and short-lived scripts. Most of it
stopped at BlackBerry 10 in 2016 and needs a Windows toolchain to build. This is a
small, self-contained replacement: point it at an extracted firmware, a mounted image
or a live QNX target and get a report you can act on.

It is a clean-room implementation: no code taken from other QNX tools, and no QNX
proprietary files are distributed here.

## Install

```bash
pip install -e .          # or, without installing anything:
python -m qnxsec.cli --help
```

## Use

```bash
qnxsec file /path/to/binary                     # card for one binary
qnxsec file /path/to/binary --json
qnxsec firmware /path/to/extracted-firmware     # analyse a tree
qnxsec firmware / --exclude proc sys --targets 20
qnxsec firmware / --json --details > report.json
```

## What it reports

Per binary:

- protections: canary, NX, PIE, RELRO (partial/full), FORTIFY;
- which ones are missing, plus a score;
- QNX surface: `resmgr_attach`, `name_attach`, `MsgReceive`/`MsgSend`, `procmgr_ability`,
  `iofunc_*`, `dispatch_*`, shared memory, timers;
- privilege symbols: `setuid`, `setgid`, `chroot`, `sysctl`, `chown`;
- execution and classic risk symbols: `system`, `popen`, `exec*`, `dlopen`, `strcpy`,
  `sprintf`, `gets`;
- strings of interest: `/pps/`, `/dev/shmem`, `/dev/mem`, `/proc/boot`, `/dev/name`,
  configuration files, secrets.

For a tree:

- counts, architectures, protection coverage in percent;
- setuid/setgid binaries and what they are missing;
- a ranked list of targets (for example: setuid, no canary, publishes in `/dev`);
- QNX system surface and recurring hints.

## Roadmap

- IFS image extraction: pull the boot image filesystem out of a firmware dump;
- decompression of compressed QNX ELF (`iwlyfmbp`, LZO/UCL);
- on-device review script for QNX 7/8, with a summary and a diff between two runs;
- testing against real QNX images (Raspberry Pi quick-start image, QEMU x86 target).

## Tests

Fixtures are compiled at test time with explicit flags, so results do not depend on the
hardening defaults of the distribution:

```bash
pip install -e ".[dev]"
pytest -q
```

Real QNX images used for manual testing are never part of this repository: they are
proprietary. Keep your own copies outside the working tree.

## Scope

Static analysis only, for systems you own or are authorised to test.

## License

MIT.
