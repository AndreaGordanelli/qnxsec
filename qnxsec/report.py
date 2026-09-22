"""Rendering: a card for one binary, a summary for a firmware, JSON.

The summary keeps the signals at the bottom, not the top: the reader wants the picture
first and the lines to act on afterwards.
"""
from __future__ import annotations

import json


def _yes_no(value) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "not declared"


def card_text(card: dict) -> str:
    lines = [f"{card['name']}  ·  {card.get('file_type', '?')}"]
    if card.get("note"):
        lines.append(f"  note: {card['note']}")
    if card.get("file_type") == "elf":
        protections = card["protections"]
        lines += [
            f"  architecture: {card['architecture']}   type: {card['type']}"
            + ("   QNX: yes" if card.get("qnx") else ""),
            f"  protections: canary {_yes_no(protections['canary'])}"
            f" · NX {_yes_no(protections['nx'])} · PIE {_yes_no(protections['pie'])}"
            f" · RELRO {protections['relro']} · FORTIFY {_yes_no(protections['fortify'])}",
        ]
        if card["setuid"] or card["setgid"]:
            privileges = " + ".join(name for name, active in (("setuid", card["setuid"]),
                                                              ("setgid", card["setgid"]))
                                    if active)
            lines.append(f"  file privileges: {privileges}")
        if card["missing_protections"]:
            lines.append(f"  missing: {', '.join(card['missing_protections'])}")
        if card["surface"]:
            lines.append("  surface: " + "; ".join(item["label"] for item in card["surface"]))
        if card["execution"]:
            lines.append("  execution: " + "; ".join(item["label"]
                                                     for item in card["execution"]))
        if card["risky_functions"]:
            lines.append("  risky functions: " + ", ".join(card["risky_functions"]))
        if card["hints"]:
            lines.append("  hints:")
            for hint in card["hints"][:10]:
                lines.append(f"    - {hint['label']}: {hint['string']}")
        lines.append(f"  score: {card['score']}"
                     + ("   <- worth a look" if card["target"] else ""))
    return "\n".join(lines)


def summary_text(summary: dict, count: int = 15) -> str:
    lines = [f"Firmware: {summary['root']}",
             f"  files examined: {summary['files']} · ELF: {summary['elf']}"
             + (f" · QNX compressed: {summary['compressed']}" if summary["compressed"] else "")
             + (f" · other binaries: {summary['other_binaries']}"
                if summary["other_binaries"] else ""),
             "  architectures: " + (", ".join(f"{key} ({value})" for key, value in
                                              sorted(summary["architectures"].items(),
                                                     key=lambda item: -item[1])) or "none")]

    protections = summary["protections"]
    if protections["count"]:
        total = protections["count"]
        lines.append("  protections present: "
                     + " · ".join(f"{name} {protections[name] * 100 // total}%"
                                  for name in ("canary", "pie", "nx", "relro")))
        lines.append("  without canary: " + ", ".join(protections["without_canary"][:8])
                     + (" ..." if len(protections["without_canary"]) > 8 else "")
                     if protections["without_canary"] else "  without canary: none")

    if summary["privileged"]:
        lines.append(f"  binaries with privileges ({len(summary['privileged'])}):")
        for item in summary["privileged"][:10]:
            lines.append("    - " + item)

    lines.append("")
    lines.append("SIGNALS")
    lines.append(f"  targets to look at first: {len(summary['targets'])}")
    for item in summary["targets"][:count]:
        lines.append("    " + item)
    if summary["surface"]:
        lines.append("  system surface:")
        for label, amount in sorted(summary["surface"].items(), key=lambda item: -item[1])[:12]:
            lines.append(f"    - {label}: {amount}")
    if summary["hints"]:
        lines.append("  recurring hints:")
        for label, amount in sorted(summary["hints"].items(), key=lambda item: -item[1])[:10]:
            lines.append(f"    - {label}: {amount}")
    return "\n".join(lines)


def to_json(data) -> str:
    return json.dumps(data, ensure_ascii=False, indent=1, sort_keys=False)
