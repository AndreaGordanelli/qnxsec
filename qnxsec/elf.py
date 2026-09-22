"""Lettore ELF essenziale, solo libreria standard.

Serve a guardare i binari di un firmware QNX senza dipendenze esterne: intestazione,
segmenti (per NX e RELRO), sezioni, simboli dinamici (per canary e superficie QNX),
librerie richieste e stringhe notevoli.

Tutto in sola lettura: nessun file viene eseguito.
"""
from __future__ import annotations

import re
import struct
from pathlib import Path

MAGIA = b"\x7fELF"
MAGIA_COMPRESSO_QNX = b"iwlyfmbp"          # ELF QNX compresso (LZO/UCL)

_SCHEMI_STRINGHE: dict[int, re.Pattern] = {}


def _schema_stringhe(minimo: int) -> re.Pattern:
    """Espressione per le stringhe stampabili, preparata una volta per lunghezza minima."""
    if minimo not in _SCHEMI_STRINGHE:
        _SCHEMI_STRINGHE[minimo] = re.compile(rb"[\x20-\x7e]{%d,}" % max(1, minimo))
    return _SCHEMI_STRINGHE[minimo]


ORDINE = {1: "<", 2: ">"}
CLASSE = {1: 32, 2: 64}
TIPO_FILE = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
MACCHINE = {
    3: "x86", 8: "mips", 20: "ppc", 21: "ppc64", 40: "arm", 42: "sh",
    50: "ia64", 62: "x86-64", 183: "aarch64", 243: "riscv",
}
# segmenti che ci interessano
PT_INTERP, PT_DYNAMIC, PT_GNU_STACK, PT_GNU_RELRO = 3, 2, 0x6474E551, 0x6474E552
PF_X, PF_W, PF_R = 1, 2, 4
SHT_SYMTAB, SHT_DYNSYM, SHT_STRTAB = 2, 11, 3
# voci dinamiche
DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH, DT_BIND_NOW, DT_FLAGS = 1, 14, 15, 29, 24, 30
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW, DF_1_NOW = 0x8, 0x1
SHT_NOTE = 7


class ErroreElf(Exception):
    """Il file non è un ELF leggibile."""


class Elfo:
    """Un file ELF aperto in memoria, letto e interpretato quel tanto che basta."""

    def __init__(self, percorso: str | Path):
        self.percorso = Path(percorso)
        self.dati = self.percorso.read_bytes()
        if len(self.dati) < 64 or not self.dati.startswith(MAGIA):
            raise ErroreElf("non è un ELF")
        self.compresso = self.dati.startswith(MAGIA_COMPRESSO_QNX)
        if self.compresso:
            raise ErroreElf("ELF compresso QNX (iwlyfmbp): va scompattato prima")

        self.classe = CLASSE.get(self.dati[4], 0)
        self.ordine = ORDINE.get(self.dati[5], "")
        if not self.classe or not self.ordine:
            raise ErroreElf("classe o byte order non riconosciuti")
        self.dimensione = len(self.dati)
        self._intestazione()
        self._segmenti()
        self._sezioni()
        self._simboli()
        self._dinamica()

    # ------------------------------------------------------------------ basi

    def _leggi(self, formato: str, offset: int):
        dimensione = struct.calcsize(formato)
        if offset + dimensione > len(self.dati):
            raise ErroreElf("struttura oltre la fine del file")
        return struct.unpack_from(self.ordine + formato, self.dati, offset)

    def _intestazione(self) -> None:
        if self.classe == 64:
            (self.tipo, self.macchina, _, self.entry, self.phoff, self.shoff, self.flags,
             _, self.phentsize, self.phnum, self.shentsize, self.shnum,
             self.shstrndx) = self._leggi("HHIQQQIHHHHHH", 16)
        else:
            (self.tipo, self.macchina, _, self.entry, self.phoff, self.shoff, self.flags,
             _, self.phentsize, self.phnum, self.shentsize, self.shnum,
             self.shstrndx) = self._leggi("HHIIIIIHHHHHH", 16)

    def _segmenti(self) -> None:
        self.segmenti = []
        for indice in range(self.phnum):
            offset = self.phoff + indice * self.phentsize
            try:
                if self.classe == 64:
                    tipo, flags, off, vaddr, _, filesz, memsz, _ = self._leggi("IIQQQQQQ", offset)
                else:
                    tipo, off, vaddr, _, filesz, memsz, flags, _ = self._leggi("IIIIIIII", offset)
            except ErroreElf:
                break
            self.segmenti.append({"tipo": tipo, "flags": flags, "offset": off, "vaddr": vaddr,
                                  "filesz": filesz, "memsz": memsz})

    def _sezioni(self) -> None:
        self.sezioni = []
        if not self.shoff:
            return
        for indice in range(self.shnum):
            offset = self.shoff + indice * self.shentsize
            try:
                if self.classe == 64:
                    (nome, tipo, flags, addr, off, size, link, info, align,
                     entsize) = self._leggi("IIQQQQIIQQ", offset)
                else:
                    (nome, tipo, flags, addr, off, size, link, info, align,
                     entsize) = self._leggi("IIIIIIIIII", offset)
            except ErroreElf:
                break
            self.sezioni.append({"nome_off": nome, "tipo": tipo, "flags": flags, "addr": addr,
                                 "offset": off, "size": size, "link": link, "info": info,
                                 "align": align, "entsize": entsize, "nome": ""})

        # nomi delle sezioni
        if self.shstrndx < len(self.sezioni):
            base = self.sezioni[self.shstrndx]
            for sezione in self.sezioni:
                sezione["nome"] = self._stringa(base["offset"], base["size"], sezione["nome_off"])

    def _stringa(self, offset: int, limite: int, posizione: int) -> str:
        if posizione >= limite or offset + posizione >= len(self.dati):
            return ""
        fine = self.dati.find(b"\0", offset + posizione, offset + limite)
        if fine < 0:
            fine = min(offset + limite, len(self.dati))
        return self.dati[offset + posizione:fine].decode("utf-8", "replace")

    def _simboli(self) -> None:
        """Nomi dai simboli dinamici e, se c'è, dalla tabella completa."""
        self.simboli: set[str] = set()
        for sezione in self.sezioni:
            if sezione["tipo"] not in (SHT_DYNSYM, SHT_SYMTAB) or not sezione["entsize"]:
                continue
            if sezione["link"] >= len(self.sezioni):
                continue
            stringhe = self.sezioni[sezione["link"]]
            quanti = sezione["size"] // sezione["entsize"]
            for indice in range(quanti):
                offset = sezione["offset"] + indice * sezione["entsize"]
                try:
                    if self.classe == 64:
                        nome_off = self._leggi("I", offset)[0]
                    else:
                        nome_off = self._leggi("I", offset)[0]
                except ErroreElf:
                    break
                nome = self._stringa(stringhe["offset"], stringhe["size"], nome_off)
                if nome:
                    self.simboli.add(nome)

    def _dinamica(self) -> None:
        self.richieste: list[str] = []
        self.rpath: list[str] = []
        self.bind_now = False
        for sezione in self.sezioni:
            if sezione["nome"] != ".dynamic" and sezione["tipo"] != 6:
                continue
            quanti = sezione["size"] // (16 if self.classe == 64 else 8)
            for indice in range(quanti):
                offset = sezione["offset"] + indice * (16 if self.classe == 64 else 8)
                try:
                    if self.classe == 64:
                        tag, valore = self._leggi("QQ", offset)
                    else:
                        tag, valore = self._leggi("II", offset)
                except ErroreElf:
                    break
                if tag == DT_NEEDED:
                    self.richieste.append(self._stringa_dinamica(valore))
                elif tag in (DT_RPATH, DT_RUNPATH):
                    testo = self._stringa_dinamica(valore)
                    if testo:
                        self.rpath.append(testo)
                elif tag == DT_BIND_NOW or (tag == DT_FLAGS and valore & DF_BIND_NOW) or \
                        (tag == DT_FLAGS_1 and valore & DF_1_NOW):
                    self.bind_now = True

    def _stringa_dinamica(self, posizione: int) -> str:
        for sezione in self.sezioni:
            if sezione["tipo"] == SHT_STRTAB and sezione["nome"] in (".dynstr", ".strtab"):
                return self._stringa(sezione["offset"], sezione["size"], posizione)
        return ""

    # ------------------------------------------------------------- proprietà

    @property
    def architettura(self) -> str:
        nome = MACCHINE.get(self.macchina, f"machine {self.macchina}")
        return f"{nome}-{self.classe}"

    @property
    def tipo_nome(self) -> str:
        return TIPO_FILE.get(self.tipo, f"tipo {self.tipo}")

    @property
    def eseguibile(self) -> bool:
        return self.tipo in (2, 3) and bool(self.segmenti)

    @property
    def pie(self) -> bool:
        """Posizione indipendente: ET_DYN con interprete. ET_EXEC = indirizzi fissi."""
        return self.tipo == 3 and self.interprete != ""

    @property
    def interprete(self) -> str:
        for segmento in self.segmenti:
            if segmento["tipo"] == PT_INTERP:
                try:
                    return self._stringa(segmento["offset"], segmento["offset"] + 512, 0)
                except ErroreElf:
                    return ""
        return ""

    @property
    def nx(self) -> bool | None:
        """True = stack non eseguibile. None = il compilatore non l'ha dichiarato."""
        for segmento in self.segmenti:
            if segmento["tipo"] == PT_GNU_STACK:
                return not bool(segmento["flags"] & PF_X)
        return None

    @property
    def relro(self) -> str:
        if not any(segmento["tipo"] == PT_GNU_RELRO for segmento in self.segmenti):
            return "assente"
        return "completa" if self.bind_now else "parziale"

    @property
    def canary(self) -> bool:
        return any(nome.startswith("__stack_chk") for nome in self.simboli)

    @property
    def fortify(self) -> bool:
        return any(nome.endswith("_chk") or nome == "__memcpy_chk" for nome in self.simboli)

    def ha_simbolo(self, *nomi: str) -> bool:
        return any(nome in self.simboli for nome in nomi)

    def stringhe(self, minimo: int = 5) -> set[str]:
        """Stringhe stampabili, come `strings` ma in casa: una scansione, non un ciclo per byte."""
        schema = _schema_stringhe(minimo)
        return {pezzo.decode("ascii", "replace") for pezzo in schema.findall(self.dati)}

    def __repr__(self) -> str:
        return f"<Elfo {self.percorso.name} {self.architettura} {self.tipo_nome}>"


def e_elf(percorso: str | Path) -> bool:
    """Vero se il file è un ELF (anche compresso QNX)."""
    try:
        with open(percorso, "rb") as maniglia:
            testa = maniglia.read(8)
    except OSError:
        return False
    return testa.startswith(MAGIA) or testa.startswith(MAGIA_COMPRESSO_QNX)


def compr_elf_qnx(percorso: str | Path) -> bool:
    """Vero se è un ELF QNX compresso (i firmware QNX li comprimono così)."""
    try:
        with open(percorso, "rb") as maniglia:
            return maniglia.read(8).startswith(MAGIA_COMPRESSO_QNX)
    except OSError:
        return False
