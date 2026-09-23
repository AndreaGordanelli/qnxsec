# Roadmap

What is worth doing next, most useful first. Each item says why it matters and how
anyone can tell it is done; nothing here is a promise about a date.

The standing constraints are the project's shape, not a phase: standard library
only, read-only (nothing that is analysed is ever executed), no QNX proprietary
file in the repository, and results that someone else can reproduce from a dump
they own.

## Done — the floor this builds on

- ELF reader: protections, QNX surface symbols, required libraries, strings.
- IFS: signature scan in both byte orders, entry walk, extraction with modes,
  chain of images, boot script, and the symlink target offset that only a real
  6.3 image exposed.
- Compressed images: startup header, the chunk chain read one chunk at a time,
  and both algorithms QNX uses — LZO1X and UCL/NRV2B — each checked against
  streams from the reference libraries rather than from an encoder written here.
- `iwlyfmbp` container structure, firmware tree ranking, IPC surface map with
  Graphviz/Mermaid export, boot script signals, and the end-to-end `dump`.
- `diff`: what changed between two builds of one binary, with address shifts told
  apart from real changes.
- CI on Python 3.10–3.13 with the reference libraries installed, so the decoder
  tests run instead of skipping.

## Next

### 1. Land the corrections that are still local

The PIE denominator counted over programs (`EXEC` or PIE) instead of every ELF,
`.sym` sidecars excluded from the counts, `sym_offset` measured from the start of
the path, and the reference helpers looking for their library outside the loader
path instead of failing the suite. *Why:* two of these change the numbers a
reader acts on, and one is a parser bug against real firmware. *Done when:*

main reports the same percentages as a hand count on a known tree, and a fresh
clone runs or cleanly skips every decoder test.

### 2. On-device collector

`qnxsec` reads a dump; a live QNX system is the same information through a
different door. A small script the reviewer runs *on the target* (or over the
serial console) that writes one JSON document — running processes with their
images, published names under `/dev` and `/pps`, `pidin`-style memory and
privilege facts, setuid binaries, `mount`, the boot script — which the existing
analysis then accepts as if it had come from an IFS.

*Why:* the interesting findings are about what a system actually exposes, and
nothing else in the QNX tooling space does this without a Windows toolchain.
*Done when:* the same `surface` and `firmware` output can be produced from a live
QEMU target and from its image, and the two agree.

### 3. Named rules with severity

Today the checks are a list of facts (canary present, `system` referenced). Turn
them into named rules with a severity, a CWE where one applies, and a stable
identifier, so a report can be diffed between two runs and a finding can be
quoted without re-reading the code that produced it.

*Why:* "missing RELRO" repeated on four hundred binaries is noise; a rule with a
name and a reason can be triaged, suppressed with a justification, and compared
over time. *Done when:* `qnxsec file --json` carries rule ids, and the collector
of item 2 can be run twice against the same target with only real changes shown.

### 4. Robustness as a security property

A tool that parses hostile input must not fall over on it. A corpus of images —
the ones the tests build plus the real ones that can be shared — fed to the IFS,
chunk-chain and container parsers, with every failure a returned error rather
than a traceback, and the corpus growing from whatever it finds.

*Why:* a crash in the reviewer's tool during an incident is worse than a missing
feature. *Done when:* the corpus runs in CI and no parser raises anything but its
own exception type.

### 5. Move the method into the repository

The workflow that produced the codec findings — booting a QNX image in QEMU,
cross-compiling for the target, moving files in over the user-mode network,
running an unmodified vendor `.so` on Linux under a `PT_GNU_STACK` patch, diffing
two builds to isolate a fix — lives outside the project. It belongs in `docs/`,
next to the code it explains.

*Why:* the next person to use this tool needs the method, not only the results.
*Done when:* `docs/` carries it and the README links to it.

## Later

### 6. Coverage of the other QNX targets

Everything is validated on 8.0 x86-64 plus one 6.3 image. QNX 7.0/7.1 and the
`aarch64le` target are the ones the advisories keep naming. Feed the same
analyses an aarch64 SDP tree and a Raspberry Pi quick-start image and fix what
turns out to be an assumption.

*Done when:* `file`, `firmware` and `ifs` have been run over both, with the
differences recorded rather than smoothed over.

### 7. Component inventory for CVE work

Given an SDP installation or a build history, list every component with its
version, BuildID, hash and path, in a form that can be joined against a CVE list
— which builds of which component are in front of you, and which of them a given
advisory covers.

*Why:* this is the manual step between "a CVE mentions libimg" and "here is the
build I have", and it is mechanical enough to automate. *Done when:* a table for
one SDP tree can be produced and re-produced, and a known CVE can be located in
it.

### 8. Symbol sidecars in the analysis

QNX ships a `.sym` file next to most binaries. Today they are excluded from the
counts (correctly) and otherwise ignored; they can instead name the functions a
binary actually calls, making "who calls `system()`" answerable per function and
letting `diff` compare builds whose symbols were stripped.

*Done when:* `diff` uses sidecar names when the stripped files carry none, and a
call-graph summary exists for one component.

### 9. Release hygiene

A tag per meaningful change, a changelog, and an install route that does not
assume a checkout (`pipx install`). Also a short "how to cite a finding from this
tool" section, so a report can point at a version.

## Out of scope, deliberately

- Writing or crafting images, or anything that executes what is analysed.
- Redistributing QNX media, samples or binaries: the tests build their own
  fixtures and the real files stay on the machine that owns the licence.
- Anything that needs a QNX toolchain at *analysis* time: the reference tools are
  for the tests, not for the user's run.
