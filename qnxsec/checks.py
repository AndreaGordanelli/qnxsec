"""Controlli su un singolo binario: protezioni presenti, superficie QNX, indizi nelle stringhe.

L'idea è rispondere a due domande diverse:
  - quanto è *sfruttabile* questo binario (canary, PIE, NX, RELRO, FORTIFY);
  - quanta *superficie* espone (resource manager, canali IPC, abilità, comandi eseguiti).

Nessuna esecuzione: si legge e basta.
"""
from __future__ import annotations

from pathlib import Path

from .elf import Elfo, ErroreElf, compr_elf_qnx, e_elf

# simboli che dicono "questo processo parla con il resto del sistema"
SUPERFICIE_QNX = {
    "resmgr_attach": "resource manager (pubblica in /dev)",
    "name_attach": "canale IPC con nome",
    "message_attach": "gestore di messaggi",
    "pulse_attach": "gestore di pulse",
    "MsgReceive": "riceve messaggi",
    "MsgSend": "invia messaggi",
    "MsgReply": "risponde ai messaggi",
    "MsgDeliverEvent": "consegna eventi",
    "MsgReceivePulse": "riceve pulse",
    "procmgr_ability": "abilità di processo",
    "secpol": "policy di sicurezza",
    "iofunc_": "libreria risorse (iofunc)",
    "dispatch_": "dispatch dei messaggi",
    "ThreadCtl": "controllo thread (operazioni privilegiate)",
    "shm_open": "memoria condivisa",
    "mq_open": "code di messaggi POSIX",
    "timer_create": "timer",
    "inotify": "notifiche file",
}

# simboli che dicono "questo processo può cambiare i privilegi"
PRIVILEGIO = {
    "setuid": "cambia utente",
    "seteuid": "cambia utente effettivo",
    "setresuid": "cambia utente reale/effettivo",
    "setgid": "cambia gruppo",
    "setegid": "cambia gruppo effettivo",
    "setgroups": "cambia gruppi",
    "chroot": "cambia radice",
    "sysctl": "parametri di kernel",
    "chmod": "cambia permessi",
    "fchmod": "cambia permessi",
    "chown": "cambia proprietario",
    "fchown": "cambia proprietario",
}

# simboli di esecuzione e funzioni storicamente insidiose
ESECUZIONE = {
    "system": "esegue comandi di shell",
    "popen": "esegue comandi di shell",
    "execve": "esegue programmi",
    "execl": "esegue programmi",
    "execvp": "esegue programmi",
    "posix_spawn": "avvia processi",
    "spawn": "avvia processi",
    "dlopen": "carica librerie a runtime",
}
INSIDIOSE = {"strcpy", "strcat", "sprintf", "gets", "mktemp", "alloca", "vsprintf", "scanf"}

# percorsi e parole che valgono un secondo sguardo: sottostringhe, non espressioni,
# perché su un firmware intero la differenza di velocità si sente tutta.
INDIZI: list[tuple[tuple[str, ...], str, bool]] = [
    (("/pps/",), "PPS: oggetti pubblicati", False),
    (("/dev/shmem",), "memoria condivisa in /dev/shmem", False),
    (("/dev/mem",), "accesso diretto alla memoria fisica", False),
    (("/proc/boot",), "immagine di boot", False),
    (("/dev/name",), "namespace IPC", False),
    (("/dev/io-",), "driver I/O", False),
    (("LD_PRELOAD", "LD_LIBRARY_PATH"), "variabili di caricamento librerie", False),
    ((".conf",), "file di configurazione", False),
    (("password", "passwd", "secret", "api_key", "api-key", "token="),
     "parola chiave o segreto", True),
    (("slog2", "/dev/slog"), "log di sistema", False),
    (("pidin", "on -t", "/proc/"), "comandi e percorsi di sistema", True),
    (("debug", "dumper", "backdoor"), "indizio di debug", True),
]


def _simboli_in(elfo: Elfo, tabella: dict) -> list[dict]:
    trovati = []
    for chiave, etichetta in tabella.items():
        if elfo.ha_simbolo(chiave):
            trovati.append({"simbolo": chiave, "etichetta": etichetta})
    return trovati


def e_qnx(elfo: Elfo) -> bool:
    """Dice se il binario è QNX: dai simboli, dall'interprete o dalle stringhe tipiche."""
    if any(nome.startswith(("Msg", "resmgr_", "iofunc_", "dispatch_", "procmgr_", "secpol"))
           for nome in elfo.simboli):
        return True
    if "qnx" in elfo.interprete.lower() or "procnto" in elfo.interprete.lower():
        return True
    return any(nome.startswith(("libc.so", "libc-")) and "qnx" in nome.lower()
               for nome in elfo.richieste)


def protezioni(elfo: Elfo) -> dict:
    return {
        "canary": elfo.canary,
        "nx": elfo.nx,
        "pie": elfo.pie,
        "relro": elfo.relro,
        "fortify": elfo.fortify,
    }


def mancanti(elfo: Elfo) -> list[str]:
    """Protezioni assenti, in ordine di quanto pesano per chi attacca."""
    assenti = []
    if not elfo.canary:
        assenti.append("canary")
    if not elfo.pie and elfo.eseguibile:
        assenti.append("PIE")
    if elfo.nx is False:
        assenti.append("NX")
    if elfo.relro == "assente":
        assenti.append("RELRO")
    return assenti


def indizi_stringhe(elfo: Elfo, limite: int = 25) -> list[dict]:
    trovati, visti = [], set()
    for stringa in elfo.stringhe():
        minuscola = stringa.lower()
        for parole, etichetta, senza_maiuscole in INDIZI:
            if any(parola in (minuscola if senza_maiuscole else stringa) for parola in parole):
                chiave = (etichetta, stringa[:120])
                if chiave not in visti:
                    visti.add(chiave)
                    trovati.append({"etichetta": etichetta, "stringa": stringa[:120]})
                break
    return trovati[:limite]


def scheda(percorso: str | Path, modo: int | None = None, stringhe: bool = True) -> dict:
    """Scheda completa di un file: protezioni, superficie, indizi, punteggio.

    `modo` è il modo del file sul filesystem (per vedere setuid/setgid); se non c'è,
    i bit di privilegio restano sconosciuti. `stringhe=False` salta l'estrazione delle
    stringhe, che su un binario molto grande è la parte più lenta.
    """
    percorso = Path(percorso)
    base = {"percorso": str(percorso), "nome": percorso.name, "dimensione": percorso.stat().st_size
            if percorso.exists() else 0}

    setuid = bool(modo is not None and modo & 0o4000)
    setgid = bool(modo is not None and modo & 0o2000)
    base["setuid"], base["setgid"] = setuid, setgid

    if compr_elf_qnx(percorso):
        base.update({"tipo_file": "elf-compresso-qnx", "nota":
                     "ELF compresso QNX (iwlyfmbp): va scompattato prima di analizzarlo"})
        return base
    if not e_elf(percorso):
        base.update({"tipo_file": "non-elf"})
        return base

    try:
        elfo = Elfo(percorso)
    except ErroreElf as errore:
        base.update({"tipo_file": "elf-illeggibile", "nota": str(errore)})
        return base
    except OSError as errore:
        base.update({"tipo_file": "errore", "nota": str(errore)})
        return base

    superficie = _simboli_in(elfo, SUPERFICIE_QNX)
    privilegio = _simboli_in(elfo, PRIVILEGIO)
    esecuzione = _simboli_in(elfo, ESECUZIONE)
    insidiose = sorted(nome for nome in elfo.simboli if nome in INSIDIOSE)
    protezioni_ = protezioni(elfo)
    assenti = mancanti(elfo)

    punteggio = 0
    punteggio += 3 if setuid else 0
    punteggio += 2 if setgid else 0
    punteggio += 2 * len([a for a in assenti if a in ("canary", "NX")])
    punteggio += 1 * len([a for a in assenti if a in ("PIE", "RELRO")])
    punteggio += 2 if esecuzione else 0
    punteggio += 1 if insidiose else 0
    punteggio += 2 if superficie else 0

    bersaglio = bool(superficie or setuid) and bool({"canary", "PIE", "NX"} & set(assenti))

    base.update({
        "tipo_file": "elf",
        "qnx": e_qnx(elfo),
        "architettura": elfo.architettura,
        "tipo": elfo.tipo_nome,
        "protezioni": protezioni_,
        "protezioni_assenti": assenti,
        "superficie": superficie,
        "privilegio": privilegio,
        "esecuzione": esecuzione,
        "funzioni_insidiose": insidiose,
        "richieste": sorted(elfo.richieste),
        "rpath": elfo.rpath,
        "indizi": indizi_stringhe(elfo) if stringhe else [],
        "punteggio": punteggio,
        "bersaglio": bersaglio,
    })
    return base
