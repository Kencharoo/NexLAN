"""Zentrale Pfade und Konstanten der Netzverwaltung."""
from pathlib import Path

# --- Eigene Daten -----------------------------------------------------------
ETC = Path("/etc/netzverwaltung")
STATE_FILE = ETC / "netz.yaml"
AUTH_FILE = ETC / "auth.json"
VAR = Path("/var/lib/netzverwaltung")
BACKUP_DIR = VAR / "backups"

# --- Fremde Dateien, die wir erzeugen ---------------------------------------
# Alles Verwaltete traegt das Praefix "nv-". Was dieses Praefix nicht hat,
# fasst die App nicht an -- das schuetzt die handgepflegten Policies
# (lan-to-switch, switchnet-to-switch, vlans-egress, gateway-*, libvirt-*).
PREFIX = "nv-"
DNSMASQ_DIR = Path("/etc/dnsmasq.d")
FIREWALLD_ZONES = Path("/etc/firewalld/zones")
FIREWALLD_POLICIES = Path("/etc/firewalld/policies")

# Die vier VLAN-Zonen existieren bereits von Hand und behalten ihre Namen,
# damit die NM-Verbindungen und der laufende Betrieb nicht brechen. Die App
# uebernimmt sie beim Import und schreibt sie danach selbst.
ADOPTED_ZONES_MARKER = VAR / "adopted-zones"

# --- Netzumgebung -----------------------------------------------------------
UPLINK_ZONE = "FedoraServer"   # eno1, traegt Masquerade Richtung FRITZ!Box
VLAN_PARENT = "eno2"           # Trunk zum HPE Instant On 1930
SWITCH_IP = "192.168.178.3"
LAN_SUBNET = "192.168.178.0/24"
PRIVATE_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
SWITCH_PORTS = [("443", "tcp"), ("4443", "tcp"), ("80", "tcp"), ("8080", "tcp")]

# --- Betrieb ----------------------------------------------------------------
LEASES_FILE = Path("/var/lib/dnsmasq/dnsmasq.leases")
LISTEN_PORT = 8090
ROLLBACK_SECONDS = 120         # Frist zum Bestaetigen, sonst automatisch zurueck
ROLLBACK_UNIT = "nv-rollback"  # transiente systemd-Unit

# Dienste, die in der Zugriffsmatrix pro VLAN angehakt werden koennen.
# Links der firewalld-Name, rechts das Label in der Oberflaeche.
HOST_SERVICES = [
    ("dhcp", "DHCP"),
    ("dns", "DNS"),
    ("ssh", "SSH"),
    ("samba", "Dateifreigaben (Samba)"),
]
# Serverdienste, die als Port veroeffentlicht sind (Podman-Stack).
HOST_PORTS = [
    ("80/tcp", "Homarr (Startseite)"),
    ("3000/tcp", "Rocket.Chat"),
    ("6875/tcp", "BookStack"),
    ("7575/tcp", "GLPI"),
    ("8010/tcp", "Paperless-ngx"),
    ("8080/tcp", "Nextcloud"),
    ("9980/tcp", "Collabora"),
    ("3142/tcp", "apt-cacher-ng"),
    ("9090/tcp", "Cockpit"),
    (f"{LISTEN_PORT}/tcp", "Netzverwaltung"),
]
