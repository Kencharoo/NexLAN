"""Datenmodell und Validierung.

Die YAML unter /etc/netzverwaltung/netz.yaml ist die einzige Wahrheit. Alles
andere (dnsmasq-Configs, firewalld-Zonen und -Policies) wird daraus erzeugt.
Wer die YAML von Hand editiert, muss danach einmal "Anwenden" druecken.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field, asdict

from . import config

NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,13}$")
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
LEASE_RE = re.compile(r"^(\d+[mhd]|infinite)$")

# Namen, die nicht als VLAN-Name taugen: bestehende Interfaces und die
# firewalld-Zonen, die wir bewusst in Ruhe lassen.
RESERVED_NAMES = {
    "lo", "eno1", "eno2", "virbr0", "idrac", "vlans", "libvirt",
    config.UPLINK_ZONE.lower(), "public", "trusted", "drop", "block",
    "internal", "external", "dmz", "home", "work", "nm-shared",
}


class ValidationError(Exception):
    """Sammelt alle Probleme, damit die Oberflaeche sie auf einmal anzeigen kann."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("; ".join(problems))


@dataclass
class Reservation:
    mac: str
    ip: str
    name: str = ""


@dataclass
class Dhcp:
    enabled: bool = True
    start: str = ""
    end: str = ""
    lease: str = "12h"


@dataclass
class Access:
    """Was dieses VLAN erreichen darf."""
    internet: bool = True          # raus via eno1, private Netze bleiben gesperrt
    haupt_lan: bool = False        # 192.168.178.0/24 (Lehrerrechner, FRITZ!Box)
    switch_gui: bool = False       # Weboberflaeche des Instant On 1930
    vlans: list[str] = field(default_factory=list)   # andere VLANs
    services: list[str] = field(default_factory=lambda: ["dhcp", "dns"])
    ports: list[str] = field(default_factory=list)


@dataclass
class DnsFilter:
    enabled: bool = False
    lists: list[str] = field(default_factory=list)  # Namen aus filter.yaml
    block: list[str] = field(default_factory=list)  # eigene Sperrdomains
    allow: list[str] = field(default_factory=list)  # Ausnahmen


@dataclass
class Vlan:
    name: str
    vlan_id: int
    address: str                    # Serveradresse inkl. Praefix, z.B. 192.168.10.1/24
    description: str = ""
    parent: str = config.VLAN_PARENT
    dhcp: Dhcp = field(default_factory=Dhcp)
    reservations: list[Reservation] = field(default_factory=list)
    access: Access = field(default_factory=Access)
    dns_filter: DnsFilter = field(default_factory=DnsFilter)

    @property
    def interface(self) -> ipaddress.IPv4Interface:
        return ipaddress.ip_interface(self.address)

    @property
    def network(self) -> ipaddress.IPv4Network:
        return self.interface.network

    @property
    def gateway(self) -> str:
        return str(self.interface.ip)

    @property
    def netmask(self) -> str:
        return str(self.network.netmask)

    @property
    def nm_connection(self) -> str:
        return f"vlan-{self.name}"


@dataclass
class State:
    version: int = 1
    vlans: list[Vlan] = field(default_factory=list)

    def get(self, name: str) -> Vlan | None:
        return next((v for v in self.vlans if v.name == name), None)

    def to_dict(self) -> dict:
        return {"version": self.version, "vlans": [asdict(v) for v in self.vlans]}

    @classmethod
    def from_dict(cls, raw: dict) -> "State":
        vlans = []
        for item in raw.get("vlans") or []:
            item = dict(item)
            item["dhcp"] = Dhcp(**(item.get("dhcp") or {}))
            item["access"] = Access(**(item.get("access") or {}))
            item["dns_filter"] = DnsFilter(**(item.get("dns_filter") or {}))
            item["reservations"] = [Reservation(**r) for r in item.get("reservations") or []]
            vlans.append(Vlan(**item))
        return cls(version=int(raw.get("version", 1)), vlans=vlans)


def validate(state: State) -> None:
    """Prueft den Gesamtzustand. Wirft ValidationError mit allen Problemen."""
    problems: list[str] = []
    seen_names: set[str] = set()
    seen_ids: set[int] = set()
    networks: list[tuple[str, ipaddress.IPv4Network]] = []

    lan = ipaddress.ip_network(config.LAN_SUBNET)

    for v in state.vlans:
        p = f"VLAN „{v.name}“"

        if not NAME_RE.match(v.name or ""):
            problems.append(
                f"{p}: Name muss mit einem Kleinbuchstaben beginnen und darf nur "
                f"Kleinbuchstaben, Ziffern und Bindestriche enthalten (max. 14 Zeichen)."
            )
        if v.name in RESERVED_NAMES:
            problems.append(f"{p}: Dieser Name ist vom System belegt.")
        if v.name in seen_names:
            problems.append(f"{p}: Name ist doppelt vergeben.")
        seen_names.add(v.name)

        if not 1 <= v.vlan_id <= 4094:
            problems.append(f"{p}: VLAN-ID {v.vlan_id} liegt nicht zwischen 1 und 4094.")
        if v.vlan_id in seen_ids:
            problems.append(f"{p}: VLAN-ID {v.vlan_id} ist doppelt vergeben.")
        seen_ids.add(v.vlan_id)

        try:
            iface = v.interface
            net = iface.network
        except ValueError:
            problems.append(f"{p}: „{v.address}“ ist keine gueltige Adresse mit Praefix (z.B. 192.168.50.1/24).")
            continue

        if iface.ip == net.network_address or iface.ip == net.broadcast_address:
            problems.append(f"{p}: {iface.ip} ist Netz- bzw. Broadcast-Adresse und taugt nicht als Gateway.")
        if net.prefixlen > 30:
            problems.append(f"{p}: Praefix /{net.prefixlen} ist zu klein fuer ein Client-Netz.")
        if net.overlaps(lan):
            problems.append(f"{p}: {net} ueberschneidet sich mit dem Haupt-LAN {lan}.")

        for other_name, other_net in networks:
            if net.overlaps(other_net):
                problems.append(f"{p}: {net} ueberschneidet sich mit VLAN „{other_name}“ ({other_net}).")
        networks.append((v.name, net))

        problems += _validate_dhcp(v, net, p)
        problems += _validate_access(v, state, p)

    if problems:
        raise ValidationError(problems)


def _validate_dhcp(v: Vlan, net: ipaddress.IPv4Network, p: str) -> list[str]:
    problems: list[str] = []
    if v.dhcp.enabled:
        if not LEASE_RE.match(v.dhcp.lease or ""):
            problems.append(f"{p}: Lease-Zeit „{v.dhcp.lease}“ ist ungueltig (z.B. 12h, 30m, 2d, infinite).")
        try:
            start = ipaddress.ip_address(v.dhcp.start)
            end = ipaddress.ip_address(v.dhcp.end)
        except ValueError:
            problems.append(f"{p}: DHCP-Bereich enthaelt keine gueltigen IP-Adressen.")
        else:
            if start not in net or end not in net:
                problems.append(f"{p}: DHCP-Bereich {start}–{end} liegt nicht vollstaendig in {net}.")
            elif start > end:
                problems.append(f"{p}: DHCP-Bereich beginnt ({start}) hinter seinem Ende ({end}).")
            elif v.interface.ip >= start and v.interface.ip <= end:
                problems.append(
                    f"{p}: Die Serveradresse {v.gateway} liegt im DHCP-Bereich und "
                    f"koennte an einen Client vergeben werden."
                )

    seen_macs: set[str] = set()
    seen_ips: set[str] = set()
    for r in v.reservations:
        mac = (r.mac or "").lower()
        if not MAC_RE.match(mac):
            problems.append(f"{p}: „{r.mac}“ ist keine gueltige MAC-Adresse (Format aa:bb:cc:dd:ee:ff).")
        elif mac in seen_macs:
            problems.append(f"{p}: MAC {mac} ist doppelt reserviert.")
        seen_macs.add(mac)

        try:
            ip = ipaddress.ip_address(r.ip)
        except ValueError:
            problems.append(f"{p}: Reservierung {r.mac} hat keine gueltige IP-Adresse.")
            continue
        if ip not in net:
            problems.append(f"{p}: Reservierte Adresse {ip} liegt nicht in {net}.")
        if ip == v.interface.ip:
            problems.append(f"{p}: {ip} ist die Adresse des Servers selbst.")
        if r.ip in seen_ips:
            problems.append(f"{p}: Adresse {r.ip} ist doppelt reserviert.")
        seen_ips.add(r.ip)
    return problems


def _validate_access(v: Vlan, state: State, p: str) -> list[str]:
    problems: list[str] = []
    known = {x.name for x in state.vlans}
    for peer in v.access.vlans:
        if peer == v.name:
            problems.append(f"{p}: Kann sich nicht selbst als Nachbar-VLAN haben.")
        elif peer not in known:
            problems.append(f"{p}: Nachbar-VLAN „{peer}“ existiert nicht.")
    if v.access.services and "dhcp" not in v.access.services and v.dhcp.enabled:
        problems.append(
            f"{p}: DHCP ist aktiv, aber der Dienst „DHCP“ ist in der Zugriffsmatrix "
            f"nicht freigegeben – Clients bekommen dann keine Adresse."
        )
    if "dns" not in v.access.services:
        problems.append(
            f"{p}: Ohne freigegebenen DNS-Dienst koennen die Clients keine Namen "
            f"aufloesen, weil der Server als DNS-Server verteilt wird."
        )
    return problems
