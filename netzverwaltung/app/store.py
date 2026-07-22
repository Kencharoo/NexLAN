"""Laden und Speichern der Wahrheitsdatei."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import yaml

from . import config
from .model import State, validate

HEADER = """\
# Netzverwaltung -- Wahrheitsdatei fuer VLANs, DHCP und Zugriffsrechte.
#
# Diese Datei darf von Hand bearbeitet werden. Damit die Aenderung wirksam
# wird, danach in der Weboberflaeche einmal "Aenderungen anwenden" druecken
# (oder: netzverwaltung-apply). Die erzeugten Dateien unter /etc/dnsmasq.d
# und /etc/firewalld werden dabei ueberschrieben -- dort nichts editieren.
"""


def load() -> State:
    if not config.STATE_FILE.exists():
        return State()
    raw = yaml.safe_load(config.STATE_FILE.read_text(encoding="utf-8")) or {}
    return State.from_dict(raw)


def save(state: State) -> None:
    """Schreibt atomar, damit ein Absturz mittendrin keine halbe Datei hinterlaesst."""
    validate(state)
    config.ETC.mkdir(parents=True, exist_ok=True)
    body = yaml.safe_dump(
        state.to_dict(), allow_unicode=True, sort_keys=False, default_flow_style=False
    )
    _atomic_write(config.STATE_FILE, HEADER + body, mode=0o640)


def _atomic_write(path: Path, content: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


atomic_write = _atomic_write
