#!/bin/bash
# Installiert die Netzverwaltung. Idempotent -- laesst sich zum Aktualisieren
# beliebig oft erneut ausfuehren.
set -euo pipefail

ZIEL=/opt/netzverwaltung
QUELLE="$(cd "$(dirname "$0")" && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "Bitte mit sudo ausfuehren." >&2
  exit 1
fi

echo "== Abhaengigkeiten =="
dnf install -y --setopt=install_weak_deps=False \
  python3-fastapi python3-uvicorn python3-jinja2 python3-pyyaml python3-python-multipart

echo "== Programmdateien nach $ZIEL =="
install -d -m 0755 "$ZIEL"
rm -rf "$ZIEL/app"
cp -r "$QUELLE/app" "$ZIEL/app"
install -d -m 0755 "$ZIEL/bin"
install -m 0755 "$QUELLE/bin/netzverwaltung-apply" "$ZIEL/bin/"
install -m 0755 "$QUELLE/bin/netzverwaltung-rollback" "$ZIEL/bin/"
install -m 0644 "$QUELLE/README.md" "$ZIEL/README.md"
ln -sf "$ZIEL/bin/netzverwaltung-apply" /usr/local/sbin/netzverwaltung-apply
ln -sf "$ZIEL/bin/netzverwaltung-rollback" /usr/local/sbin/netzverwaltung-rollback

echo "== Datenverzeichnisse =="
install -d -m 0750 /etc/netzverwaltung
install -d -m 0750 /var/lib/netzverwaltung
install -d -m 0750 /var/lib/netzverwaltung/backups
install -d -m 0750 /var/lib/netzverwaltung/filter

echo "== Dummy-Link fuer den DNS-Filter =="
# Traegt beide Adressen: .1 fuer die Filterinstanz, .2 fuer den Haupt-dnsmasq.
# Der Link ist rein serverintern, deshalb Zone "trusted".
if ! nmcli -t -f NAME connection show | grep -qx nvdns; then
  nmcli connection add type dummy con-name nvdns ifname nvdns \
    ipv4.method manual ipv4.addresses 10.99.99.1/24,10.99.99.2/24 \
    ipv6.method disabled connection.zone trusted connection.autoconnect yes
  nmcli connection up nvdns
fi

echo "== systemd =="
install -m 0644 "$QUELLE/systemd/netzverwaltung.service" /etc/systemd/system/
install -m 0644 "$QUELLE/systemd/dnsmasq-filter.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now netzverwaltung.service

echo "== Firewall =="
# Nur im Haupt-LAN erreichbar. Welche VLANs zusaetzlich duerfen, entscheidet
# spaeter die Zugriffsmatrix.
firewall-cmd --permanent --zone=FedoraServer --add-port=8090/tcp >/dev/null
firewall-cmd --reload >/dev/null

echo
echo "Fertig. Weiter im Browser:"
echo "  http://$(hostname -I | awk '{print $1}'):8090/"
echo
echo "1. Passwort setzen"
echo "2. unter \"Bestehenden Aufbau uebernehmen\" den Ist-Zustand einlesen"
echo "3. pruefen, dass \"Ausstehende Aenderungen\" danach leer ist"
