"""Aktive DHCP-Leases lesen und den VLANs zuordnen."""
from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass

from . import config
from .model import State


@dataclass
class Lease:
    mac: str
    ip: str
    hostname: str
    expires: int
    vlan: str

    @property
    def hostname_display(self) -> str:
        return self.hostname if self.hostname and self.hostname != "*" else "—"

    @property
    def remaining(self) -> str:
        secs = self.expires - int(time.time())
        if secs <= 0:
            return "abgelaufen"
        if secs < 3600:
            return f"{secs // 60} min"
        if secs < 86400:
            return f"{secs // 3600} h {(secs % 3600) // 60} min"
        return f"{secs // 86400} d"

    @property
    def sort_key(self) -> tuple:
        try:
            return (self.vlan, int(ipaddress.ip_address(self.ip)))
        except ValueError:
            return (self.vlan, 0)


def read(state: State) -> list[Lease]:
    if not config.LEASES_FILE.exists():
        return []

    networks = [(v.name, v.network) for v in state.vlans]
    leases: list[Lease] = []
    for line in config.LEASES_FILE.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        expires, mac, ip, hostname = parts[0], parts[1], parts[2], parts[3]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        vlan = next((name for name, net in networks if addr in net), "")
        leases.append(Lease(
            mac=mac.lower(), ip=ip, hostname=hostname,
            expires=int(expires), vlan=vlan or "(nicht verwaltet)",
        ))
    return sorted(leases, key=lambda l: l.sort_key)


def reserved_macs(state: State) -> set[str]:
    return {r.mac.lower() for v in state.vlans for r in v.reservations}


def suggest_ip(state: State, vlan_name: str) -> str:
    """Naechste freie Adresse unterhalb des DHCP-Bereichs -- dort stoert eine
    Reservierung die dynamische Vergabe am wenigsten."""
    vlan = state.get(vlan_name)
    if not vlan:
        return ""
    taken = {r.ip for r in vlan.reservations} | {vlan.gateway}
    try:
        first_dynamic = ipaddress.ip_address(vlan.dhcp.start)
    except ValueError:
        first_dynamic = list(vlan.network.hosts())[-1]

    for host in vlan.network.hosts():
        if host >= first_dynamic:
            break
        if str(host) not in taken:
            return str(host)
    return ""
