"""Vergleichen, Anwenden, Zuruecknehmen.

Der gefaehrlichste Teil der App: hier wird am laufenden Router geschraubt.
Deshalb drei Sicherungen.

1. Vorher wird jede verwaltete Datei in ein Tar-Archiv gesichert.
2. Jede Aenderung ist als Diff sichtbar, bevor sie passiert.
3. Nach dem Anwenden laeuft eine Frist. Wer sich aussperrt, kann nicht mehr
   bestaetigen -- dann stellt eine transiente systemd-Unit den alten Stand
   wieder her, auch wenn die Weboberflaeche selbst nicht mehr erreichbar ist.
"""
from __future__ import annotations

import difflib
import json
import subprocess
import tarfile
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree

from . import config, importer, render
from .model import State
from .store import atomic_write

PENDING = config.VAR / "pending.json"


class ApplyError(Exception):
    pass


@dataclass
class Change:
    path: str
    action: str            # "neu" | "geaendert" | "geloescht"
    diff: str

    @property
    def kind(self) -> str:
        if "/dnsmasq" in self.path:
            return "DHCP/DNS"
        if "/policies/" in self.path:
            return "Routing"
        if "/zones/" in self.path:
            return "Serverdienste"
        return "Sonstiges"


# --- Bestandsaufnahme -------------------------------------------------------

def managed_paths(state: State) -> set[str]:
    """Alle Dateien, fuer die sich die App zustaendig fuehlt -- erzeugte wie
    auch die beim Import uebernommenen Zonen."""
    paths = set(render.render_all(state))
    paths |= {str(p) for p in config.DNSMASQ_DIR.glob(f"{config.PREFIX}*.conf")}
    paths |= {str(p) for p in config.FIREWALLD_POLICIES.glob(f"{config.PREFIX}*.xml")}
    for name in adopted_zones():
        paths.add(str(config.FIREWALLD_ZONES / f"{name}.xml"))

    # Handgeschriebene Policies, die dieselben VLANs regeln wie die erzeugten.
    # Sie muessen mit weg, sonst laesst die alte Regel weiter durch, waehrend
    # die Matrix "gesperrt" anzeigt. Beim ersten Anwenden nach dem Import ist
    # das der eigentliche Umschaltmoment.
    for name in importer.obsolete_policies(state):
        paths.add(str(config.FIREWALLD_POLICIES / f"{name}.xml"))

    # Dasselbe fuer dnsmasq: die handgeschriebene vlans.conf wuerde jeden
    # DHCP-Bereich ein zweites Mal definieren.
    doomed, _ = importer.obsolete_dnsmasq_files(state)
    paths |= {str(p) for p in doomed}
    return paths


def adopted_zones() -> list[str]:
    if not config.ADOPTED_ZONES_MARKER.exists():
        return []
    return [l.strip() for l in config.ADOPTED_ZONES_MARKER.read_text().splitlines() if l.strip()]


def set_adopted_zones(names: list[str]) -> None:
    atomic_write(config.ADOPTED_ZONES_MARKER, "\n".join(sorted(set(names))) + "\n")


def diff(state: State) -> list[Change]:
    """Was wuerde sich aendern, wenn wir jetzt anwenden?"""
    target = render.render_all(state)
    changes: list[Change] = []

    for path in sorted(managed_paths(state)):
        p = Path(path)
        old = p.read_text(encoding="utf-8") if p.exists() else None
        new = target.get(path)

        if old == new:
            continue
        if new is None:
            changes.append(Change(path, "geloescht", _unified(old or "", "", path)))
        elif old is None:
            changes.append(Change(path, "neu", _unified("", new, path)))
        else:
            changes.append(Change(path, "geaendert", _unified(old, new, path)))
    return changes


def _unified(old: str, new: str, path: str) -> str:
    return "".join(difflib.unified_diff(
        old.splitlines(keepends=True), new.splitlines(keepends=True),
        fromfile=f"a{path}", tofile=f"b{path}", n=2,
    ))


# --- Anwenden ---------------------------------------------------------------

def preflight(target: dict[str, str]) -> list[str]:
    """Prueft die erzeugten Dateien, bevor eine davon die Platte beruehrt.

    Kostet nichts und faengt genau die Fehlerklasse ab, die sonst erst beim
    Neuladen auffaellt -- dann aber mit halb geschriebener Konfiguration.
    """
    problems: list[str] = []

    for path, content in target.items():
        if path.endswith(".xml"):
            try:
                ElementTree.fromstring(content)
            except ElementTree.ParseError as exc:
                problems.append(f"{Path(path).name} ist kein gueltiges XML: {exc}")

    with tempfile.TemporaryDirectory() as tmp:
        for path, content in target.items():
            if not path.endswith(".conf"):
                continue
            probe = Path(tmp) / Path(path).name
            probe.write_text(content, encoding="utf-8")
            proc = subprocess.run(
                ["dnsmasq", "--test", f"--conf-file={probe}"],
                capture_output=True, text=True,
            )
            if proc.returncode != 0:
                problems.append(f"{probe.name}: {proc.stderr.strip() or proc.stdout.strip()}")

    return problems


def apply(state: State, *, with_rollback: bool = True) -> dict:
    """Schreibt alles, laedt die Dienste neu und plant die Ruecknahme ein."""
    target = render.render_all(state)

    problems = preflight(target)
    if problems:
        raise ApplyError(
            "Die erzeugte Konfiguration ist fehlerhaft, es wurde nichts geaendert: "
            + "; ".join(problems)
        )

    backup = _backup(managed_paths(state))

    try:
        for path, content in target.items():
            atomic_write(Path(path), content)
        for path in managed_paths(state) - set(target):
            Path(path).unlink(missing_ok=True)

        # firewalld zuerst: die Zonen muessen existieren, bevor NetworkManager
        # ein Interface hineinlegen kann.
        _run(["firewall-cmd", "--reload"])
        _sync_interfaces(state)
        _reload_dnsmasq(state)
    except Exception as exc:
        _restore(backup)
        _reload_all(state, best_effort=True)
        raise ApplyError(f"Anwenden fehlgeschlagen, alter Stand wiederhergestellt: {exc}") from exc

    set_adopted_zones([v.name for v in state.vlans])

    if with_rollback:
        _schedule_rollback(backup)
        deadline = time.time() + config.ROLLBACK_SECONDS
        atomic_write(PENDING, json.dumps({"backup": str(backup), "deadline": deadline}))
        return {"backup": str(backup), "deadline": deadline}
    return {"backup": str(backup), "deadline": None}


def confirm() -> None:
    """Bestaetigt die letzte Aenderung und stoppt die geplante Ruecknahme."""
    _run(["systemctl", "stop", f"{config.ROLLBACK_UNIT}.timer"], check=False)
    _run(["systemctl", "stop", f"{config.ROLLBACK_UNIT}.service"], check=False)
    PENDING.unlink(missing_ok=True)


def pending() -> dict | None:
    if not PENDING.exists():
        return None
    data = json.loads(PENDING.read_text())
    if data.get("deadline", 0) < time.time():
        return None
    return data


def rollback_now() -> None:
    """Wird von der transienten Unit aufgerufen, wenn niemand bestaetigt hat."""
    data = json.loads(PENDING.read_text()) if PENDING.exists() else None
    if not data:
        return
    _restore(Path(data["backup"]))
    _reload_all(None, best_effort=True)
    PENDING.unlink(missing_ok=True)


# --- Sicherung --------------------------------------------------------------

def _backup(paths: set[str]) -> Path:
    config.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    archive = config.BACKUP_DIR / f"{stamp}.tar"
    with tarfile.open(archive, "w") as tar:
        for path in sorted(paths):
            p = Path(path)
            if p.exists():
                tar.add(path, arcname=path.lstrip("/"))
        # Merkzettel, welche Dateien es zum Sicherungszeitpunkt gab. Ohne den
        # koennten wir beim Zurueckrollen neu angelegte Dateien nicht loeschen.
        manifest = config.BACKUP_DIR / f".{stamp}.manifest"
        manifest.write_text("\n".join(sorted(paths)))
        tar.add(manifest, arcname="MANIFEST")
        manifest.unlink()
    _prune_backups()
    return archive


def _restore(archive: Path) -> None:
    with tarfile.open(archive, "r") as tar:
        manifest = tar.extractfile("MANIFEST")
        known = set(manifest.read().decode().split()) if manifest else set()
        contained = {"/" + m.name for m in tar.getmembers() if m.name != "MANIFEST"}
        # Was es vorher nicht gab, muss wieder weg.
        for path in known - contained:
            Path(path).unlink(missing_ok=True)
        for member in tar.getmembers():
            if member.name == "MANIFEST":
                continue
            data = tar.extractfile(member)
            if data:
                atomic_write(Path("/" + member.name), data.read().decode("utf-8"))


def _prune_backups(keep: int = 20) -> None:
    archives = sorted(config.BACKUP_DIR.glob("*.tar"))
    for old in archives[:-keep]:
        old.unlink(missing_ok=True)


# --- Systemseite ------------------------------------------------------------

def _sync_interfaces(state: State) -> None:
    """Legt fehlende VLAN-Verbindungen an und entfernt ueberzaehlige.

    Unveraenderte Verbindungen werden bewusst nicht angefasst: ein
    "nmcli connection up" reisst das Interface kurz herunter, und das wuerde
    bei jedem Anwenden alle Clients im VLAN treffen.
    """
    existing = _nm_vlan_connections()
    wanted = {v.nm_connection: v for v in state.vlans}

    for name, vlan in wanted.items():
        if name not in existing:
            _run([
                "nmcli", "connection", "add", "type", "vlan",
                "con-name", name, "ifname", vlan.name,
                "dev", vlan.parent, "id", str(vlan.vlan_id),
                "ip4", vlan.address,
                "ipv4.method", "manual", "ipv6.method", "disabled",
                "connection.zone", vlan.name,
                "connection.autoconnect", "yes",
            ])
            _run(["nmcli", "connection", "up", name], check=False)
            continue

        current = importer.nm_fields(name, ["vlan.id", "vlan.parent", "ipv4.addresses",
                                            "connection.zone", "GENERAL.STATE"])
        unchanged = (
            current.get("vlan.id") == str(vlan.vlan_id)
            and current.get("vlan.parent") == vlan.parent
            and current.get("ipv4.addresses") == vlan.address
            and current.get("connection.zone") == vlan.name
        )
        if unchanged and current.get("GENERAL.STATE") == "activated":
            continue

        _run([
            "nmcli", "connection", "modify", name,
            "ipv4.addresses", vlan.address,
            "vlan.id", str(vlan.vlan_id),
            "vlan.parent", vlan.parent,
            "connection.zone", vlan.name,
        ])
        _run(["nmcli", "connection", "up", name], check=False)

    for name in existing - set(wanted):
        _run(["nmcli", "connection", "delete", name], check=False)


def _nm_vlan_connections() -> set[str]:
    out = _run(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"]).stdout
    names = set()
    for line in out.splitlines():
        name, _, typ = line.rpartition(":")
        if typ == "vlan" and name.startswith("vlan-"):
            names.add(name)
    return names


def _reload_dnsmasq(state: State | None, check: bool = True) -> None:
    _run(["systemctl", "restart", "dnsmasq"], check=check)

    if state is None:
        # Ruecknahme: welche VLANs gefiltert werden sollten, wissen wir hier
        # nicht mehr. Laeuft die Instanz, bekommt sie die zurueckgeholte
        # Konfiguration; laeuft sie nicht, bleibt sie aus.
        _run(["systemctl", "try-restart", "dnsmasq-filter"], check=False)
        return

    # Die Filterinstanz laeuft nur, solange mindestens ein VLAN sie braucht.
    if any(v.dns_filter.enabled for v in state.vlans):
        _run(["systemctl", "enable", "--now", "dnsmasq-filter"], check=check)
        _run(["systemctl", "restart", "dnsmasq-filter"], check=check)
    else:
        _run(["systemctl", "disable", "--now", "dnsmasq-filter"], check=False)


def _reload_all(state: State | None, best_effort: bool = False) -> None:
    check = not best_effort
    _run(["firewall-cmd", "--reload"], check=check)
    _reload_dnsmasq(state, check=check)


def _schedule_rollback(backup: Path) -> None:
    _run(["systemctl", "stop", f"{config.ROLLBACK_UNIT}.timer"], check=False)
    _run([
        "systemd-run",
        f"--unit={config.ROLLBACK_UNIT}",
        f"--on-active={config.ROLLBACK_SECONDS}",
        "--description=Netzverwaltung: nicht bestaetigte Aenderung zuruecknehmen",
        "/opt/netzverwaltung/bin/netzverwaltung-rollback",
    ])


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise ApplyError(f"{' '.join(cmd)}: {proc.stderr.strip() or proc.stdout.strip()}")
    return proc
