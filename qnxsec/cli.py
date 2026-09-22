"""Riga di comando.

    qnxsec file <binario>          scheda di un singolo binario
    qnxsec firmware <cartella>     analisi di un albero (firmware estratto o sistema vivo)
"""
from __future__ import annotations

import argparse
import sys

from . import __version__, checks, firmware, report


def costruisci_parser() -> argparse.ArgumentParser:
    analizzatore = argparse.ArgumentParser(
        prog="qnxsec",
        description="Analisi statica di firmware e sistemi QNX: protezioni, superficie IPC, "
                    "bersagli da guardare per primi. Non esegue niente.")
    analizzatore.add_argument("--versione", action="version", version=f"qnxsec {__version__}")
    sottocomandi = analizzatore.add_subparsers(dest="comando", required=True)

    singolo = sottocomandi.add_parser("file", help="scheda di un binario")
    singolo.add_argument("percorso", help="file da analizzare")
    singolo.add_argument("--json", action="store_true", help="uscita JSON")

    albero = sottocomandi.add_parser("firmware", help="analizza un albero di file")
    albero.add_argument("radice", help="cartella del firmware o radice del sistema")
    albero.add_argument("--json", action="store_true", help="uscita JSON")
    albero.add_argument("--bersagli", type=int, default=15,
                        help="quanti bersagli elencare (predefinito 15)")
    albero.add_argument("--escludi", nargs="*", default=["proc", "sys"],
                        help="nomi di cartella da saltare (predefinito: proc sys)")
    albero.add_argument("--schede", action="store_true",
                        help="nel JSON includi anche la scheda di ogni binario")
    return analizzatore


def main(argv: list[str] | None = None) -> int:
    scelte = costruisci_parser().parse_args(argv)

    if scelte.comando == "file":
        scheda = checks.scheda(scelte.percorso)
        print(report.in_json(scheda) if scelte.json else report.scheda_testo(scheda))
        return 0

    if scelte.comando == "firmware":
        esito = firmware.analizza(scelte.radice, scelte.bersagli, tuple(scelte.escludi))
        if scelte.json:
            print(report.in_json(esito if scelte.schede else {"riassunto": esito["riassunto"]}))
        else:
            print(report.riassunto_testo(esito["riassunto"], scelte.bersagli))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
