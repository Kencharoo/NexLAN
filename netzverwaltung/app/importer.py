"""Liest den bestehenden, von Hand gepflegten Aufbau in das Datenmodell ein.

Laeuft einmal bei der Einrichtung. Ziel ist, dass direkt nach dem Import ein
"Anwenden" nichts veraendern wuerde -- der Ist-Zustand muss sich also exakt
abbilden lassen. Was nicht abbildbar ist, wird gemeldet statt stillschweigend
verworfen.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
from xml.etree import ElementTree

from . import config
from .model import Access, Dhcp, Reservation, State, Vlan


def import_system() -> tuple[State, list[str]]:
    """Liefert den erkannten Zustand und Hinweise auf alles Unklare."""
    notes: list[str] = []
    vlans_by_iface = _vlans_from_networkmanager(notes)
    _dhcp_from_dnsmasq(vlans_by_iface, notes)
    _access_from_firewalld(vlans_by_iface, notes)

    state = State(vlans=sorted(vlans_by_iface.values(), key=lambda v: v.vlan_id))
    return state, notes


def _vlans_from_networkmanager(notes: list[str]) -> dict[str, Vlan]:
    """NetworkManager ist die verlaesslichste Quelle fuer ID, Eltern-Interface
    und Adresse."""
    vlans: dict[str, Vlan] = {}
    out = _run(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"])
    for line in out.splitlines():
        name, _, typ = line.rpartition(":")
        if typ != "vlan":
            continue
        detail = nm_fields(name, ["vlan.id", "vlan.parent", "ipv4.addresses",
                                   "connection.interface-name", "connection.zone"])
        iface = detail.get("connection.interface-name") or ""
        addresses = detail.get("ipv4.addresses") or ""
        address = addresses.split(",")[0].strip()
        if not iface or not address:
            notes.append(f"Verbindung „{name}“ uebersprungen: kein Interface oder keine feste IPv4-Adresse.")
            continue
        if len(addresses.split(",")) > 1:
            notes.append(f"VLAN „{iface}“ hat mehrere IPv4-Adressen; nur {address} wird verwaltet.")

        vlans[iface] = Vlan(
            name=iface,
            vlan_id=int(detail.get("vlan.id") or 0),
            address=address,
            parent=detail.get("vlan.parent") or config.VLAN_PARENT,
            dhcp=Dhcp(enabled=False),
            access=Access(services=[], internet=False),
        )
        zone = detail.get("connection.zone")
        if zone and zone != iface:
            notes.append(
                f"VLAN „{iface}“ liegt in firewalld-Zone „{zone}“ statt in einer "
                f"gleichnamigen Zone. Die Verwaltung wuerde es nach „{iface}“ umziehen."
            )
    return vlans


def nm_fields(con: str, fields: list[str]) -> dict[str, str]:
    out = _run(["nmcli", "-t", "-f", ",".join(fields), "connection", "show", con])
    result: dict[str, str] = {}
    for line in out.splitlines():
        key, _, value = line.partition(":")
        if value and value != "--":
            result[key] = value
    return result


DHCP_RANGE = re.compile(r"^dhcp-range=set:(?P<tag>[^,]+),(?P<start>[^,]+),(?P<end>[^,]+),(?P<mask>[^,]+),(?P<lease>[^,]+)")
DHCP_HOST = re.compile(r"^dhcp-host=(?P<mac>[0-9a-fA-F:]{17}),set:(?P<tag>[^,]+),(?P<ip>[0-9.]+)(?:,(?P<name>\S+))?")


def _dhcp_from_dnsmasq(vlans: dict[str, Vlan], notes: list[str]) -> None:
    """Nur Dateien, die zu unseren VLANs gehoeren. switch-mgmt.conf beschreibt
    die Netze an eno2 und bleibt bewusst in Handarbeit."""
    for conf in sorted(config.DNSMASQ_DIR.glob("*.conf")):
        for raw in conf.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            m = DHCP_RANGE.match(line)
            if m and m["tag"] in vlans:
                v = vlans[m["tag"]]
                v.dhcp = Dhcp(enabled=True, start=m["start"], end=m["end"], lease=m["lease"])
                continue
            m = DHCP_HOST.match(line)
            if m and m["tag"] in vlans:
                vlans[m["tag"]].reservations.append(
                    Reservation(mac=m["mac"].lower(), ip=m["ip"], name=m["name"] or "")
                )

    for name, v in vlans.items():
        if not v.dhcp.enabled:
            notes.append(f"Fuer VLAN „{name}“ wurde kein DHCP-Bereich gefunden; DHCP startet ausgeschaltet.")


def _access_from_firewalld(vlans: dict[str, Vlan], notes: list[str]) -> None:
    for name, vlan in vlans.items():
        zone_file = config.FIREWALLD_ZONES / f"{name}.xml"
        if zone_file.exists():
            root = ElementTree.fromstring(zone_file.read_text(encoding="utf-8"))
            vlan.access.services = [e.get("name", "") for e in root.findall("service")]
            vlan.access.ports = [
                f"{e.get('port')}/{e.get('protocol')}" for e in root.findall("port")
            ]
        else:
            notes.append(f"Keine firewalld-Zone „{name}“ gefunden; Serverdienste starten leer.")

    for policy_file in sorted(config.FIREWALLD_POLICIES.glob("*.xml")):
        try:
            root = ElementTree.fromstring(policy_file.read_text(encoding="utf-8"))
        except ElementTree.ParseError:
            notes.append(f"Policy {policy_file.name} ist kein gueltiges XML und wird ignoriert.")
            continue

        ingress = [e.get("name") for e in root.findall("ingress-zone")]
        egress = [e.get("name") for e in root.findall("egress-zone")]
        for zone in ingress:
            vlan = vlans.get(zone or "")
            if not vlan:
                continue
            if config.UPLINK_ZONE in egress:
                vlan.access.internet = True
                vlan.access.haupt_lan = _allows_lan(root)
            elif "vlans" in egress and _mentions_switch(root):
                vlan.access.switch_gui = True
            else:
                for peer in egress:
                    if peer in vlans:
                        vlan.access.vlans.append(peer)
                    elif peer:
                        notes.append(
                            f"Policy {policy_file.name} erlaubt „{zone}“ nach „{peer}“. "
                            f"„{peer}“ ist kein verwaltetes VLAN – diese Regel wird beim "
                            f"Anwenden nicht neu erzeugt."
                        )


def _allows_lan(root: ElementTree.Element) -> bool:
    """Haupt-LAN erreichbar heisst: es gibt kein Drop, das es verbietet."""
    for rule in root.findall("rule"):
        dest = rule.find("destination")
        if dest is None:
            continue
        addr = dest.get("address", "")
        blocks_lan = addr in ("192.168.0.0/16", config.LAN_SUBNET)
        if blocks_lan and rule.find("drop") is not None:
            return False
        if blocks_lan and rule.find("reject") is not None:
            return False
    return True


def _mentions_switch(root: ElementTree.Element) -> bool:
    return any(
        (d.get("address") or "").startswith(config.SWITCH_IP)
        for d in root.iter("destination")
    )


def obsolete_dnsmasq_files(state: State) -> tuple[list[Path], list[str]]:
    """dnsmasq-Dateien, die dieselben VLANs bedienen wie die erzeugte
    nv-vlans.conf. Bleiben sie liegen, definiert dnsmasq jeden DHCP-Bereich
    zweimal und startet nicht mehr.

    Abgeloest wird nur, was sich *vollstaendig* auf verwaltete VLANs bezieht.
    Mischdateien werden gemeldet statt geloescht -- sonst raesse der Import
    Einstellungen mit weg, die niemand hier abgebildet hat.
    """
    names = {v.name for v in state.vlans}
    doomed: list[Path] = []
    warnings: list[str] = []

    for conf in sorted(config.DNSMASQ_DIR.glob("*.conf")):
        if conf.stem.startswith(config.PREFIX):
            continue
        managed, foreign = 0, 0
        for raw in conf.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if _references_vlan(line, names):
                managed += 1
            else:
                foreign += 1

        if managed and not foreign:
            doomed.append(conf)
        elif managed and foreign:
            warnings.append(
                f"{conf.name} enthaelt sowohl Einstellungen fuer verwaltete VLANs als "
                f"auch fremde Zeilen. Die Datei wird nicht angefasst – entferne die "
                f"VLAN-Zeilen dort von Hand, sonst definiert dnsmasq sie doppelt."
            )
    return doomed, warnings


def _references_vlan(line: str, names: set[str]) -> bool:
    """Bezieht sich die Zeile auf eines der verwalteten VLANs?"""
    for key, sep in (("interface=", ""), ("no-dhcp-interface=", ""),
                     ("dhcp-range=set:", ","), ("dhcp-option=tag:", ","),
                     ("dhcp-host=", "")):
        if not line.startswith(key):
            continue
        rest = line[len(key):]
        if key == "dhcp-host=":
            # dhcp-host=<mac>,set:<tag>,<ip>
            tag = next((p[4:] for p in rest.split(",") if p.startswith("set:")), "")
        elif sep:
            tag = rest.split(sep, 1)[0]
        else:
            tag = rest
        return tag.strip() in names
    return False


def obsolete_policies(state: State) -> list[str]:
    """Handgeschriebene Policies, die nach dem Import dasselbe regeln wuerden
    wie die erzeugten. Bleiben sie liegen, waere die Matrix gelogen: sie zeigt
    „gesperrt“, waehrend die alte Regel weiter durchlaesst."""
    names = {v.name for v in state.vlans}
    doomed = []
    for policy_file in sorted(config.FIREWALLD_POLICIES.glob("*.xml")):
        if policy_file.stem.startswith(config.PREFIX):
            continue
        try:
            root = ElementTree.fromstring(policy_file.read_text(encoding="utf-8"))
        except ElementTree.ParseError:
            continue
        ingress = {e.get("name") for e in root.findall("ingress-zone")}
        if ingress & names:
            doomed.append(policy_file.stem)
    return doomed


def _run(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True).stdout
