"""The IPC surface map: publishers, users, graph exports."""
from __future__ import annotations

from qnxsec import firmware, surface


def card(name: str, symbols: list[str], strings: list[str], architecture: str = "arm-32") -> dict:
    return {
        "name": name,
        "file_type": "elf",
        "architecture": architecture,
        "surface": [{"symbol": symbol, "label": f"label {symbol}"} for symbol in symbols],
        "hints": [{"label": "PPS: published objects", "string": text} for text in strings],
    }


def test_publishers_and_users_are_separated():
    cards = [
        card("devc-ser8250", ["resmgr_attach", "iofunc_"],
             ["/dev/ser1", "/dev/ser2"]),
        card("client", [], ["/dev/ser1", "/pps/system/log"]),
    ]
    surface_map = surface.from_cards(cards)
    assert [publisher.binary for publisher in surface_map.publishers] == ["devc-ser8250"]
    assert surface_map.publishers[0].names == ["/dev/ser1", "/dev/ser2"]
    assert surface_map.users["/dev/ser1"] == ["devc-ser8250", "client"]
    assert "/pps/system/log" in surface_map.unclaimed     # nobody publishes it here


def test_graph_exports_are_wellformed():
    cards = [card("net", ["name_attach"], ["/dev/socket"]),
             card("tool", [], ["/dev/socket"])]
    surface_map = surface.from_cards(cards)
    dot = surface_map.to_dot()
    assert dot.startswith("digraph surface {") and dot.rstrip().endswith("}")
    assert '"net" -> "/dev/socket" [label="publishes"' in dot
    assert '"tool" -> "/dev/socket" [label="uses"]' in dot

    mermaid = surface_map.to_mermaid()
    assert mermaid.startswith("graph LR")
    assert "net" in mermaid and "socket" in mermaid


def test_summary_is_serialisable():
    import json
    surface_map = surface.from_cards([card("a", ["resmgr_attach"], ["/dev/x"])])
    reloaded = json.loads(json.dumps(surface_map.summary()))
    assert reloaded["publishers"][0]["binary"] == "a"
    assert reloaded["names"]["/dev/x"] == 1


def test_report_has_signals():
    surface_map = surface.from_cards([card("a", ["resmgr_attach"], ["/dev/x", "/pps/y"])])
    text = surface.report(surface_map)
    assert "Publishers: 1" in text
    assert "SIGNALS" in text
    assert "/pps/y" in text


def test_end_to_end_over_a_scanned_tree(tree):
    """The fixtures carry resmgr_attach and a /pps name: the map must see them."""
    cards = firmware.analyse(tree)["cards"]
    surface_map = surface.from_cards(cards)
    assert surface_map.publishers
    names = {name for publisher in surface_map.publishers for name in publisher.names}
    assert any(name.startswith("/pps/") for name in names)
