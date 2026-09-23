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
qnxsec diff old.so new.so                        # what changed between two builds
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
- **both payloads are decompressed**, block by block, with decoders written here and
  checked against streams produced by the reference libraries themselves;
- **images compressed as a whole are read too**: QNX writes the filesystem as a chain of
  compressed chunks behind a startup header, which is the usual shape of flash firmware,
  and both algorithms are handled there as well.

Two builds of the same binary:

- which functions changed and by how much, which were added, which were removed;
- which differ only in the addresses they refer to inside the same file — the same code
  once those references are masked, which is what makes a one-function fix visible on a
  file where everything moved.

## Not there yet

- On-device review script for QNX 7/8, with a summary and a diff between two runs.
- Testing against real QNX images (Raspberry Pi quick-start image, QEMU x86 target).

## Tests

Fixtures are compiled at test time with explicit flags, so results do not depend on the
hardening defaults of the distribution. IFS images are assembled in memory by a builder
written from the documented layout, so a disagreement about an offset fails the tests.

Both decoders are checked against streams produced by the real libraries through
`tools/lzo_ref.c` and `tools/ucl_ref.c`: a shared misunderstanding of the format cannot
pass unnoticed, because the reference bytes come from the libraries QNX links against.
Where no compiler, no liblzo2 or no libucl is available those tests skip instead of
passing quietly.

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
