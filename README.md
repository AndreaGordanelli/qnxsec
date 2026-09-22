# qnxsec

Static analysis for QNX firmware and systems: pull the boot image filesystem out of a
firmware dump, see what each binary is protected with, what system surface it exposes,
what the boot script really starts, and which binaries are worth looking at first.

Written from scratch, standard library only, read-only. It never executes what it
analyses and never needs a QNX toolchain to run.

## Why

QNX tooling has a long history of good research and short-lived scripts. Most of it
stopped at BlackBerry 10 in 2016 and needs a Windows toolchain to build. This is a
small, self-contained replacement: point it at a firmware dump, an extracted tree or a
live QNX target and get a report you can act on.

It is a clean-room implementation: no code taken from other QNX tools, and no QNX
proprietary files are distributed here.

## Install

```bash
pip install -e .          # or, without installing anything:
python -m qnxsec.cli --help
```

## Use

```bash
qnxsec dump firmware.bin --extract unpacked      # the whole pipeline in one go
qnxsec ifs firmware.bin --script                 # list the IFS images inside a dump
qnxsec bootscript unpacked/image1/proc/boot/.script
qnxsec compressed unpacked/image1/bin/devc-ser8250
qnxsec firmware unpacked/image1 --targets 20     # per-binary analysis of a tree
qnxsec surface unpacked/image1 --dot graph.dot   # who publishes which QNX name
qnxsec file /path/to/binary --json
```

Nothing is executed and nothing is written outside the directory you pass to `--extract`.

## What it reports

From a firmware dump:

- every `imagefs` signature found, both byte orders, and the chain of images;
- the entry list with modes, owners, symlinks and devices;
- extraction that preserves modes, including setuid bits;
- the boot script found in the image, analysed (see below).

From a boot script or buildfile:

- blocks (`.bootstrap`, `.script`), the commands they run, their arguments and environment;
- the services started, the devices waited for, and the image entries with their modes;
- signals: world-writable permissions, services exposed at boot (`telnetd`, `ftpd`,
  `qconn`), the root filesystem remounted read-write, credentials sitting in the script,
  devices used without a `waitfor`.

Per binary:

- protections: canary, NX, PIE, RELRO (partial/full), FORTIFY; which ones are missing;
- QNX surface: `resmgr_attach`, `name_attach`, `MsgReceive`/`MsgSend`, `procmgr_ability`,
  `iofunc_*`, `dispatch_*`, shared memory, timers;
- privilege symbols: `setuid`, `setgid`, `chroot`, `sysctl`, `chown`;
- execution and classic risk symbols: `system`, `popen`, `exec*`, `dlopen`, `strcpy`,
  `sprintf`, `gets`;
- strings of interest: `/pps/`, `/dev/shmem`, `/dev/mem`, `/proc/boot`, configuration
  files, secrets;
- a score and a ranked list of targets for a whole tree.

Compressed binaries:

- the `iwlyfmbp` container structure: declared size, block size, algorithm
  (LZO1X or UCL/NRV2B), block map and stored sizes;
- **LZO1X payloads are decompressed**, block by block, with a decoder written here and
  checked against streams produced by the reference library itself. UCL/NRV2B is refused
  rather than guessed: it will be written the same way, against the library.

## Not there yet

- **UCL/NRV2B payloads.** The LZO1X side is written and verified; the NRV2B decoder is
  not, so `decompress()` refuses those containers instead of returning bytes nobody has
  checked.
- On-device review script for QNX 7/8, with a summary and a diff between two runs.
- Testing against real QNX images (Raspberry Pi quick-start image, QEMU x86 target).

## Tests

Fixtures are compiled at test time with explicit flags, so results do not depend on the
hardening defaults of the distribution. IFS images are assembled in memory by a builder
written from the documented layout, so a disagreement about an offset fails the tests.

The LZO1X decoder is checked against streams produced by liblzo2 itself through
`tools/lzo_ref.c`: a shared misunderstanding of the format cannot pass unnoticed, because
the reference bytes come from the library QNX links against. Where no compiler or no
liblzo2 is available those tests skip instead of passing quietly.

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
