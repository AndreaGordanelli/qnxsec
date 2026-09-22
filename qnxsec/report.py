"""Resa leggibile: scheda di un binario, riassunto di un firmware, JSON.

Il riassunto mette i segnali in fondo, non in testa: chi legge vuole prima il quadro
e poi le righe su cui agire.
"""
from __future__ import annotations

import json


def _si_no(valore) -> str:
    if valore is True:
        return "sì"
    if valore is False:
        return "no"
    return "non dichiarato"


def scheda_testo(scheda: dict) -> str:
    righe = [f"{scheda['nome']}  ·  {scheda.get('tipo_file', '?')}"]
    if scheda.get("nota"):
        righe.append(f"  nota: {scheda['nota']}")
    if scheda.get("tipo_file") == "elf":
        protezioni = scheda["protezioni"]
        righe += [
            f"  architettura: {scheda['architettura']}   tipo: {scheda['tipo']}"
            + ("   QNX: sì" if scheda.get("qnx") else ""),
            f"  protezioni: canary {_si_no(protezioni['canary'])} · NX {_si_no(protezioni['nx'])}"
            f" · PIE {_si_no(protezioni['pie'])} · RELRO {protezioni['relro']}"
            f" · FORTIFY {_si_no(protezioni['fortify'])}",
        ]
        if scheda["setuid"] or scheda["setgid"]:
            privilegi = " + ".join(n for n, attivo in (("setuid", scheda["setuid"]),
                                                       ("setgid", scheda["setgid"])) if attivo)
            righe.append(f"  privilegi sul file: {privilegi}")
        if scheda["protezioni_assenti"]:
            righe.append(f"  mancano: {', '.join(scheda['protezioni_assenti'])}")
        if scheda["superficie"]:
            righe.append("  superficie: " + "; ".join(v["etichetta"] for v in scheda["superficie"]))
        if scheda["esecuzione"]:
            righe.append("  esecuzione: " + "; ".join(v["etichetta"] for v in scheda["esecuzione"]))
        if scheda["funzioni_insidiose"]:
            righe.append("  funzioni insidiose: " + ", ".join(scheda["funzioni_insidiose"]))
        if scheda["indizi"]:
            righe.append("  indizi:")
            for indizio in scheda["indizi"][:10]:
                righe.append(f"    - {indizio['etichetta']}: {indizio['stringa']}")
        righe.append(f"  punteggio: {scheda['punteggio']}"
                     + ("   ← da guardare" if scheda["bersaglio"] else ""))
    return "\n".join(righe)


def riassunto_testo(riassunto: dict, quanti: int = 15) -> str:
    righe = [f"Firmware: {riassunto['radice']}",
             f"  file esaminati: {riassunto['file']} · ELF: {riassunto['elf']}"
             + (f" · compressi QNX: {riassunto['compressi']}" if riassunto["compressi"] else "")
             + (f" · altri binari: {riassunto['altri_binari']}" if riassunto["altri_binari"] else ""),
             f"  architetture: " + (", ".join(f"{k} ({v})" for k, v in
                                              sorted(riassunto["architetture"].items(),
                                                     key=lambda v: -v[1])) or "nessuna")]

    protezioni = riassunto["protezioni"]
    if protezioni["conta"]:
        conta = protezioni["conta"]
        righe.append("  protezioni presenti: "
                     + " · ".join(f"{nome} {protezioni[nome] * 100 // conta}%"
                                  for nome in ("canary", "pie", "nx", "relro")))
        righe.append("  senza canary: " + ", ".join(protezioni["senza_canary"][:8])
                     + (" …" if len(protezioni["senza_canary"]) > 8 else "")
                     if protezioni["senza_canary"] else "  senza canary: nessuno")

    if riassunto["privilegiati"]:
        righe.append(f"  binari con privilegi ({len(riassunto['privilegiati'])}):")
        for voce in riassunto["privilegiati"][:10]:
            righe.append("    - " + voce)

    righe.append("")
    righe.append("SINTESI")
    righe.append(f"  bersagli da guardare per primi: {len(riassunto['bersagli'])}")
    for voce in riassunto["bersagli"][:quanti]:
        righe.append("    " + voce)
    if riassunto["superficie"]:
        righe.append("  superficie di sistema:")
        for etichetta, quanti_ in sorted(riassunto["superficie"].items(),
                                         key=lambda v: -v[1])[:12]:
            righe.append(f"    - {etichetta}: {quanti_}")
    if riassunto["indizi"]:
        righe.append("  indizi ricorrenti:")
        for etichetta, quanti_ in sorted(riassunto["indizi"].items(), key=lambda v: -v[1])[:10]:
            righe.append(f"    - {etichetta}: {quanti_}")
    return "\n".join(righe)


def in_json(dati) -> str:
    return json.dumps(dati, ensure_ascii=False, indent=1, sort_keys=False)
