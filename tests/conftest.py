"""Test binaries compiled on the fly with explicit flags.

Every flag is declared, so the tests do not depend on the hardening defaults of the
distribution: the same outcome holds on any machine with a C compiler.
"""
from __future__ import annotations

import os
import shutil
import subprocess

import pytest

SOURCE = r"""
#include <stdio.h>
#include <string.h>

/* convenience names: they make QNX-looking symbols show up in the binary */
void resmgr_attach(void) {}
int  MsgReceive(void) { return 0; }

int main(int argc, char **argv) {
    char buffer[64];
    const char *object = "/pps/system/test/object";
    const char *conf = "/etc/test.conf";
    const char *secret = "password=not-real";
    if (argc > 1) {
        strcpy(buffer, argv[1]);
    }
    printf("%s %s %s\n", object, conf, secret);
    return 0;
}
"""


@pytest.fixture(scope="session")
def compiler() -> str:
    for name in ("cc", "gcc", "clang"):
        found = shutil.which(name)
        if found:
            return found
    pytest.skip("no C compiler available")


@pytest.fixture(scope="session")
def source(tmp_path_factory) -> str:
    path = tmp_path_factory.mktemp("sources") / "test.c"
    path.write_text(SOURCE)
    return str(path)


@pytest.fixture(scope="session")
def hardened_binary(compiler, source, tmp_path_factory) -> str:
    """PIE, canary, non-executable stack, full RELRO."""
    output = tmp_path_factory.mktemp("hardened") / "hardened"
    subprocess.run([compiler, "-O0", "-fstack-protector-strong", "-fPIE", "-pie",
                    "-Wl,-z,relro,-z,now", source, "-o", str(output)], check=True)
    return str(output)


@pytest.fixture(scope="session")
def bare_binary(compiler, source, tmp_path_factory) -> str:
    """Non-PIE, no canary, executable stack: the portrait of an old binary."""
    output = tmp_path_factory.mktemp("bare") / "bare"
    subprocess.run([compiler, "-O0", "-fno-stack-protector", "-no-pie", "-fno-pie",
                    "-z", "execstack", source, "-o", str(output)], check=True)
    return str(output)


@pytest.fixture
def tree(tmp_path, hardened_binary, bare_binary) -> str:
    """A fake firmware: binaries, a setuid one, a compressed QNX ELF and a folder to skip."""
    root = tmp_path / "firmware"
    (root / "bin").mkdir(parents=True)
    (root / "etc").mkdir(parents=True)
    (root / "proc" / "boot").mkdir(parents=True)

    shutil.copy(hardened_binary, root / "bin" / "hardened")
    shutil.copy(bare_binary, root / "bin" / "bare")
    shutil.copy(bare_binary, root / "bin" / "privileged")
    os.chmod(root / "bin" / "privileged", 0o4755)

    (root / "bin" / "compressed").write_bytes(b"iwlyfmbp" + b"\0" * 64)
    (root / "etc" / "test.conf").write_text("key = value\n")
    (root / "proc" / "boot" / "noise").write_text("to be excluded\n")
    return str(root)
