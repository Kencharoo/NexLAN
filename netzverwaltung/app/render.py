"""Erzeugt aus dem Zustand die tatsaechlichen Konfigurationsdateien.

Rendern ist bewusst eine reine Funktion: Zustand rein, Dateiinhalte raus.
Nichts hier schreibt auf die Platte oder ruft ein Kommando auf -- das macht
applier.py. So laesst sich jede Aenderung erst als Diff anzeigen.
"""
from __future__ import annotations

from xml.sax.saxutils import escape

from . import config
from .model import State, Vlan

# Kein doppelter Bindestrich im Text: er landet auch in einem XML-Kommentar,
# und dort ist "--" laut XML-Spezifikation verboten. firewalld weist die Datei
# sonst mit INVALID_POLICY zurueck.
GENERATED = "Erzeugt von der Netzverwaltung. Aenderungen hier gehen verloren."

# Adressen auf dem Dummy-Interface fuer die DNS-Filterung. Bewusst ausserhalb
# aller Klassennetze, damit sie von keinem VLAN-Wechsel betroffen sind.
FILTER_IP = "10.99.99.1"     # gefilterter Resolver (zweite dnsmasq-Instanz)
UPSTREAM_IP = "10.99.99.2"   # Haupt-dnsmasq, damit Filter lokale Namen kennt
FILTER_LINK = "nvdns"


def render_all(state: State) -> dict[str, str]:
    """Liefert {absoluter Pfad: Inhalt} fuer alle verwalteten Dateien."""
    files: dict[str, str] = {}

    files[str(config.DNSMASQ_DIR / f"{config.PREFIX}vlans.conf")] = _dnsmasq(state)

    for vlan in state.vlans:
        files[str(config.FIREWALLD_ZONES / f"{vlan.name}.xml")] = _zone(vlan)
        for name, xml in _policies(vlan, state).items():
            files[str(config.FIREWALLD_POLICIES / f"{name}.xml")] = xml

    if any(v.dns_filter.enabled for v in state.vlans):
        files[str(config.DNSMASQ_DIR / f"{config.PREFIX}filter-upstream.conf")] = _filter_upstream()
        files["/etc/netzverwaltung/dnsmasq-filter.conf"] = _filter_instance(state)

    return files


# --- dnsmasq ----------------------------------------------------------------

def _dnsmasq(state: State) -> str:
    lines = [f"# {GENERATED}", ""]
    for v in state.vlans:
        lines.append(f"# --- VLAN {v.vlan_id}  {v.name}  -> {v.network} ---")
        if v.description:
            lines.append(f"# {v.description}")
        lines.append(f"interface={v.name}")

        if v.dhcp.enabled:
            lines.append(
                f"dhcp-range=set:{v.name},{v.dhcp.start},{v.dhcp.end},"
                f"{v.netmask},{v.dhcp.lease}"
            )
            lines.append(f"dhcp-option=tag:{v.name},option:router,{v.gateway}")
            dns = FILTER_IP if v.dns_filter.enabled else v.gateway
            lines.append(f"dhcp-option=tag:{v.name},option:dns-server,{dns}")
            for r in v.reservations:
                host = f",{r.name}" if r.name else ""
                lines.append(f"dhcp-host={r.mac.lower()},set:{v.name},{r.ip}{host}")
        else:
            # Ohne dhcp-range bedient dnsmasq das Interface nicht -- explizit
            # ausschliessen, damit auch kein Relay-Verkehr beantwortet wird.
            lines.append(f"no-dhcp-interface={v.name}")
        lines.append("")
    return "\n".join(lines)


def _filter_upstream() -> str:
    """Der Haupt-dnsmasq lauscht zusaetzlich auf dem Dummy-Link, damit die
    Filterinstanz ihn nach lokalen Namen fragen kann, ohne von der LAN-IP
    des Servers abzuhaengen.

    Wichtig ist listen-address statt interface=: der Dummy-Link traegt beide
    Adressen, und bind-dynamic wuerde bei interface= auch die .1 belegen --
    genau den Port, den die Filterinstanz braucht.
    """
    return "\n".join([
        f"# {GENERATED}",
        "",
        f"listen-address={UPSTREAM_IP}",
        f"no-dhcp-interface={FILTER_LINK}",
        "",
    ])


def _filter_instance(state: State) -> str:
    """Zweite dnsmasq-Instanz, die nur filtert und sonst nach oben durchreicht.

    dnsmasq kann Sperrlisten nicht pro Interface unterscheiden, deshalb der
    getrennte Prozess: gefilterte VLANs bekommen per DHCP diesen Resolver.
    """
    lines = [
        f"# {GENERATED}",
        "# Gefilterter Resolver. Wird von dnsmasq-filter.service gestartet.",
        "",
        "bind-interfaces",
        f"listen-address={FILTER_IP}",
        "no-dhcp-interface=",
        "no-hosts",
        "no-resolv",
        f"server={UPSTREAM_IP}",
        "cache-size=2000",
        "",
    ]
    for v in state.vlans:
        if not v.dns_filter.enabled:
            continue
        lines.append(f"# --- {v.name} ---")
        for domain in v.dns_filter.allow:
            lines.append(f"server=/{domain}/{UPSTREAM_IP}")
        for domain in v.dns_filter.block:
            lines.append(f"address=/{domain}/")
        lines.append("")

    # Die heruntergeladenen Listen liegen als eigene Dateien daneben.
    lines.append("conf-dir=/var/lib/netzverwaltung/filter,*.conf")
    lines.append("")
    return "\n".join(lines)


# --- firewalld --------------------------------------------------------------

def _zone(vlan: Vlan) -> str:
    """Zone = was das VLAN auf dem Server selbst erreichen darf."""
    out = ['<?xml version="1.0" encoding="utf-8"?>', "<zone>",
           f"  <short>{escape(vlan.name)}</short>",
           f"  <description>{escape(vlan.description or GENERATED)}</description>"]
    for svc in vlan.access.services:
        out.append(f'  <service name="{escape(svc)}"/>')
    for port in vlan.access.ports:
        num, _, proto = port.partition("/")
        out.append(f'  <port port="{escape(num)}" protocol="{escape(proto or "tcp")}"/>')
    out.append("</zone>")
    return "\n".join(out) + "\n"


def _policies(vlan: Vlan, state: State) -> dict[str, str]:
    """Policies = was das VLAN durch den Server hindurch erreichen darf."""
    policies: dict[str, str] = {}

    if vlan.access.internet:
        policies[f"{config.PREFIX}{vlan.name}-egress"] = _egress_policy(vlan)

    if vlan.access.switch_gui:
        policies[f"{config.PREFIX}{vlan.name}-switch"] = _switch_policy(vlan)

    for peer in vlan.access.vlans:
        if state.get(peer):
            policies[f"{config.PREFIX}{vlan.name}-to-{peer}"] = _peer_policy(vlan, peer)

    return policies


def _egress_policy(vlan: Vlan) -> str:
    """Raus Richtung eno1. Private Netze werden verworfen, sonst haette jedes
    VLAN ueber den Uplink freien Zugriff aufs Haupt-LAN.

    Die Reihenfolge ist ueber priority festgeschrieben und nicht ueber die
    Position im Dokument -- firewalld sortiert Rich Rules sonst selbst.
    """
    rules = []
    if vlan.access.haupt_lan:
        rules.append(
            f'  <rule family="ipv4" priority="-100">\n'
            f'    <destination address="{config.LAN_SUBNET}"/>\n'
            f"    <accept/>\n"
            f"  </rule>"
        )
    for net in config.PRIVATE_NETS:
        rules.append(
            f'  <rule family="ipv4" priority="0">\n'
            f'    <destination address="{net}"/>\n'
            f"    <drop/>\n"
            f"  </rule>"
        )
    return _policy_xml(
        target="ACCEPT",
        ingress=vlan.name,
        egress=config.UPLINK_ZONE,
        rules=rules,
        comment=f"{vlan.name}: Internet",
    )


def _switch_policy(vlan: Vlan) -> str:
    """Zugriff auf die Weboberflaeche des Switches (192.168.178.3 an eno2).

    Masquerade ist noetig, weil der Switch als Gateway die .9 des Servers hat
    und Antworten sonst am VLAN-Netz vorbeilaufen wuerden.
    """
    rules = []
    for port, proto in config.SWITCH_PORTS:
        rules.append(
            f'  <rule family="ipv4">\n'
            f'    <destination address="{config.SWITCH_IP}/32"/>\n'
            f'    <port port="{port}" protocol="{proto}"/>\n'
            f"    <accept/>\n"
            f"  </rule>"
        )
    rules.append(
        f'  <rule family="ipv4">\n'
        f'    <destination address="{config.SWITCH_IP}/32"/>\n'
        f'    <protocol value="icmp"/>\n'
        f"    <accept/>\n"
        f"  </rule>"
    )
    return _policy_xml(
        target="REJECT",
        ingress=vlan.name,
        egress="vlans",
        rules=rules,
        comment=f"{vlan.name}: Switch-Oberflaeche",
        masquerade=True,
    )


def _peer_policy(vlan: Vlan, peer: str) -> str:
    """Erlaubt vlan -> peer. Rueckantworten laufen ueber Connection Tracking,
    die Gegenrichtung braucht also eine eigene Policy."""
    return _policy_xml(
        target="ACCEPT",
        ingress=vlan.name,
        egress=peer,
        rules=[],
        comment=f"{vlan.name} darf {peer} ansprechen",
    )


def _policy_xml(*, target: str, ingress: str, egress: str, rules: list[str],
                comment: str, masquerade: bool = False) -> str:
    out = ['<?xml version="1.0" encoding="utf-8"?>',
           f"<!-- {GENERATED} -->",
           f'<policy target="{target}">',
           f"  <short>{escape(comment)}</short>"]
    if masquerade:
        out.append("  <masquerade/>")
    out += rules
    out.append(f'  <ingress-zone name="{escape(ingress)}"/>')
    out.append(f'  <egress-zone name="{escape(egress)}"/>')
    out.append("</policy>")
    return "\n".join(out) + "\n"
