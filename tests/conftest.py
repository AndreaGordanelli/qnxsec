"""Binari di prova compilati al volo con flag espliciti.

I flag sono tutti dichiarati: il test non dipende dall'hardening predefinito della
distribuzione, quindi lo stesso esito vale su qualsiasi macchina con un compilatore C.
"""
from __future__ import annotations

import os
import shutil
import subprocess

import pytest

SORGENTE = r"""
#include <stdio.h>
#include <string.h>

/* nomi di comodo: servono a far comparire simboli QNX nel binario */
void resmgr_attach(void) {}
int  MsgReceive(void) { return 0; }

int main(int argc, char **argv) {
    char buffer[64];
    const char *oggetto = "/pps/system/prova/oggetto";
    const char *conf = "/etc/prova.conf";
    const char *segreto = "password=non-vera";
    if (argc > 1) {
        strcpy(buffer, argv[1]);
    }
    printf("%s %s %s\n", oggetto, conf, segreto);
    return 0;
}
"""


@pytest.fixture(scope="session")
def compilatore() -> str:
    for nome in ("cc", "gcc", "clang"):
        trovato = shutil.which(nome)
        if trovato:
            return trovato
    pytest.skip("nessun compilatore C disponibile")


@pytest.fixture(scope="session")
def sorgente(tmp_path_factory) -> str:
    percorso = tmp_path_factory.mktemp("sorgenti") / "prova.c"
    percorso.write_text(SORGENTE)
    return str(percorso)


@pytest.fixture(scope="session")
def binario_protetto(compilatore, sorgente, tmp_path_factory) -> str:
    """PIE, canary, stack non eseguibile, RELRO completa."""
    uscita = tmp_path_factory.mktemp("protetto") / "protetto"
    subprocess.run([compilatore, "-O0", "-fstack-protector-strong", "-fPIE", "-pie",
                    "-Wl,-z,relro,-z,now", sorgente, "-o", str(uscita)], check=True)
    return str(uscita)


@pytest.fixture(scope="session")
def binario_nudo(compilatore, sorgente, tmp_path_factory) -> str:
    """Non-PIE, senza canary, con stack eseguibile: il ritratto di un binario vecchio."""
    uscita = tmp_path_factory.mktemp("nudo") / "nudo"
    subprocess.run([compilatore, "-O0", "-fno-stack-protector", "-no-pie", "-fno-pie",
                    "-z", "execstack", sorgente, "-o", str(uscita)], check=True)
    return str(uscita)


@pytest.fixture
def albero(tmp_path, binario_protetto, binario_nudo) -> str:
    """Un finto firmware: binari, un setuid, un ELF compresso QNX e una cartella da escludere."""
    radice = tmp_path / "firmware"
    (radice / "bin").mkdir(parents=True)
    (radice / "etc").mkdir(parents=True)
    (radice / "proc" / "boot").mkdir(parents=True)

    shutil.copy(binario_protetto, radice / "bin" / "protetto")
    shutil.copy(binario_nudo, radice / "bin" / "nudo")
    shutil.copy(binario_nudo, radice / "bin" / "conprivilegi")
    os.chmod(radice / "bin" / "conprivilegi", 0o4755)

    (radice / "bin" / "compresso").write_bytes(b"iwlyfmbp" + b"\0" * 64)
    (radice / "etc" / "prova.conf").write_text("chiave = valore\n")
    (radice / "proc" / "boot" / "rumore").write_text("da escludere\n")
    return str(radice)
