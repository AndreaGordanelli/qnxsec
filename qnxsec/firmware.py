"""Scansione di un albero — firmware estratto, immagine montata o sistema QNX vivo.

Sola lettura: si guarda tutto, non si esegue e non si scrive niente su disco.
"""
from __future__ import annotations

import os
import stat
from collections import Counter
from pathlib import Path

from . import checks

DIMENSIONE_MASSIMA_STRINGHE = 64 * 1024 * 1024


def file_dell_albero(radice: str | Path, escludi: tuple[str, ...] = ()):
    """Percorre l'albero e restituisce (percorso, modo, dimensione) dei file regolari."""
    for cartella, sottocartelle, nomi in os.walk(radice, followlinks=False):
        sottocartelle.sort()
        for nome in sorted(nomi):
            percorso = Path(cartella) / nome
            if any(parte in percorso.parts for parte in escludi):
                continue
            try:
                info = percorso.stat()
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            yield percorso, info.st_mode, info.st_size


def analizza(radice: str | Path, quanti_bersagli: int = 15,
             escludi: tuple[str, ...] = (), avanzamento=None) -> dict:
    """Analizza tutti i binari dell'albero e restituisce riassunto più schede."""
    radice = Path(radice)
    schede, altri, compressi = [], 0, 0
    quanti = 0
    for percorso, modo, dimensione in file_dell_albero(radice, escludi):
        quanti += 1
        if avanzamento and quanti % 200 == 0:
            avanzamento(quanti)
        scheda = checks.scheda(percorso, modo,
                               stringhe=dimensione <= DIMENSIONE_MASSIMA_STRINGHE)
        if scheda["tipo_file"] == "elf":
            schede.append(scheda)
        elif scheda["tipo_file"] == "elf-compresso-qnx":
            compressi += 1
        elif dimensione > 0:
            altri += 1
    riassunto = riassumi(radice, schede, quanti, compressi, altri, quanti_bersagli)
    return {"riassunto": riassunto, "schede": schede}


def riassumi(radice, schede: list[dict], quanti: int, compressi: int, altri: int,
             quanti_bersagli: int) -> dict:
    elfi = [s for s in schede if s["tipo_file"] == "elf"]
    architetture = Counter(s["architettura"] for s in elfi)
    protezioni = {
        "conta": len(elfi),
        "canary": sum(1 for s in elfi if s["protezioni"]["canary"]),
        "pie": sum(1 for s in elfi if s["protezioni"]["pie"]),
        "nx": sum(1 for s in elfi if s["protezioni"]["nx"] is True),
        "relro": sum(1 for s in elfi if s["protezioni"]["relro"] != "assente"),
        "senza_canary": sorted(s["nome"] for s in elfi if not s["protezioni"]["canary"]),
    }
    privilegiati = []
    for scheda in sorted(schede, key=lambda s: -s["punteggio"]):
        if not (scheda["setuid"] or scheda["setgid"]):
            continue
        etichetta = "setuid" if scheda["setuid"] else "setgid"
        assenti = ", ".join(scheda["protezioni_assenti"]) or "niente"
        privilegiati.append(f"{scheda['nome']} ({scheda['architettura']}, {etichetta}) "
                            f"manca: {assenti}")
    superficie = Counter(voce["etichetta"] for scheda in elfi for voce in scheda["superficie"])
    indizi = Counter(voce["etichetta"] for scheda in elfi for voce in scheda["indizi"])
    bersagli = []
    for scheda in sorted(elfi, key=lambda s: (-s["punteggio"], s["nome"])):
        if not scheda["bersaglio"]:
            continue
        manca = ", ".join(scheda["protezioni_assenti"]) or "niente"
        superficie_voce = ", ".join(v["etichetta"] for v in scheda["superficie"][:2]) or "—"
        privilegio = " setuid" if scheda["setuid"] else ""
        bersagli.append(f"{scheda['punteggio']:>3}  {scheda['nome']} ({scheda['architettura']},"
                        f"{privilegio}) — manca: {manca} — {superficie_voce}")
    return {
        "radice": str(radice),
        "file": quanti,
        "elf": len(elfi),
        "compressi": compressi,
        "altri_binari": altri,
        "architetture": dict(architetture),
        "protezioni": protezioni,
        "privilegiati": privilegiati,
        "bersagli": bersagli[:quanti_bersagli],
        "bersagli_totali": len(bersagli),
        "superficie": dict(superficie),
        "indizi": dict(indizi),
    }
