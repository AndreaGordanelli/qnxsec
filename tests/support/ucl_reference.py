"""Reference UCL/NRV2B compressor, used by the tests.

Same rule as the LZO side: the decoder is checked against streams produced by
the library QNX links against, never against a compressor written here.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
SOURCE = ROOT / "tools" / "ucl_ref.c"
HELPER = ROOT / "tools" / "ucl_ref"


def path() -> Path | None:
    """Build the reference compressor once, or return None when it is impossible."""
    if not SOURCE.exists():
        return None
    if not HELPER.exists():
        compiler = shutil.which("cc") or shutil.which("gcc")
        if compiler is None:
            return None
        # Honour CFLAGS/LDFLAGS so a locally extracted libucl (not in /usr) works.
        extra = shlex.split(os.environ.get("CFLAGS", "")) + shlex.split(
            os.environ.get("LDFLAGS", ""))
        built = subprocess.run(
            [compiler, "-O2", *extra, "-o", str(HELPER), str(SOURCE), "-lucl"],
            capture_output=True, text=True)
        if built.returncode != 0:
            return None  # libucl-dev is not installed
    return HELPER


def compress(payload: bytes, workdir: Path) -> bytes:
    """Compress a payload with the reference library and return the stream."""
    helper = path()
    if helper is None:
        raise RuntimeError("the reference compressor is not available")
    source = Path(workdir) / "payload.bin"
    packed = Path(workdir) / "payload.ucl"
    source.write_bytes(payload)
    run = subprocess.run([str(helper), "compress", str(source), str(packed)],
                         capture_output=True, text=True)
    if run.returncode != 0:
        raise RuntimeError("the reference compressor failed: " + run.stderr)
    return packed.read_bytes()
