# Netzverwaltung

Weboberfläche für DHCP und Routing des Unterrichtsnetzes auf dem KlassenServer.

Deckt bewusst nur ab, was Cockpit nicht kann. Interfaces, Routen, Dienste,
Logs und Terminal bleiben in **Cockpit auf Port 9090**. Hier gibt es:

- **VLANs** anlegen, ändern, entfernen — NetworkManager-Verbindung, firewalld-Zone,
  DHCP-Bereich und Regeln in einem Vorgang
- **Geräte** — alle aktiven DHCP-Leases, per Klick zur festen Adresse
- **Zugriff** — Kreuztabelle, wer wen erreichen darf, plus Internet, Haupt-LAN,
  Switch-Oberfläche und die Dienste auf dem Server selbst
- **DNS-Filter** — gesperrte Domains je VLAN

## Wie es funktioniert

`/etc/netzverwaltung/netz.yaml` ist die einzige Wahrheit. Daraus werden erzeugt:

| Datei | Inhalt |
|---|---|
| `/etc/dnsmasq.d/nv-vlans.conf` | DHCP-Bereiche, Reservierungen, verteilte Optionen |
| `/etc/firewalld/zones/<vlan>.xml` | was das VLAN auf dem Server selbst erreichen darf |
| `/etc/firewalld/policies/nv-*.xml` | was das VLAN durch den Server hindurch erreichen darf |
| `/etc/netzverwaltung/dnsmasq-filter.conf` | Sperrlisten der zweiten dnsmasq-Instanz |

Alles Erzeugte trägt das Präfix `nv-`. Was dieses Präfix nicht hat, fasst die App
nicht an — die handgepflegten Policies `lan-to-switch`, `switchnet-to-switch`,
`vlans-egress` und `/etc/dnsmasq.d/switch-mgmt.conf` bleiben in Handarbeit.
Sie beschreiben die Netze an `eno2` samt Proxy-ARP, was sich nicht sinnvoll
generieren lässt.

Ändern und Anwenden sind getrennt. Gespeicherte Änderungen landen zuerst nur in
der YAML; erst „Anwenden“ schreibt die Dateien und lädt dnsmasq und firewalld neu.
Vorher zeigt die Oberfläche jede Änderung als Diff.

## Sich nicht aussperren

Nach dem Anwenden läuft eine Frist von 120 Sekunden. Wer nicht bestätigt, bekommt
den vorherigen Stand automatisch zurück — erledigt von einer eigenen systemd-Unit,
also auch dann, wenn die Weboberfläche selbst nicht mehr erreichbar ist.

Die Rücknahme stellt die **erzeugten Dateien** wieder her, nicht die `netz.yaml`.
Der gewünschte Zustand bleibt also erhalten und taucht danach wieder unter
„Ausstehende Änderungen“ auf. Jede Sicherung liegt unter
`/var/lib/netzverwaltung/backups/` (die letzten 20).

## DNS-Filter

dnsmasq kann Sperrlisten nicht pro Interface unterscheiden. Sobald ein VLAN
gefiltert wird, läuft deshalb eine zweite Instanz `dnsmasq-filter` auf
`10.99.99.1` (Dummy-Link `nvdns`). Gefilterte VLANs bekommen per DHCP diesen
Resolver statt der Serveradresse. Was er nicht sperrt, reicht er an den
Haupt-dnsmasq auf `10.99.99.2` weiter — so bleiben lokale Gerätenamen auflösbar.
Ungefilterte VLANs merken davon nichts.

Der Dummy-Link trägt beide Adressen und ist rein serverintern; er ändert sich
nicht mit der LAN-Adresse des Servers.

## Ohne Browser

```bash
netzverwaltung-apply --pruefen      # zeigt nur, was sich ändern würde
netzverwaltung-apply                # anwenden, mit Bestätigungsfrist
netzverwaltung-apply --bestaetigen  # innerhalb der Frist bestätigen
netzverwaltung-apply --sofort       # anwenden ohne Frist und ohne Rücknahme
```

Nützlich, wenn `netz.yaml` von Hand editiert wurde oder die Oberfläche klemmt.

## Installation und Aktualisierung

```bash
sudo ./install.sh
```

Idempotent, lässt sich zum Aktualisieren erneut ausführen. Danach im Browser auf
Port 8090 das Passwort setzen und unter „Bestehenden Aufbau übernehmen“ den
Ist-Zustand einlesen.

## Betrieb

```bash
systemctl status netzverwaltung
journalctl -u netzverwaltung -f
systemctl status dnsmasq-filter    # nur aktiv, wenn ein VLAN gefiltert wird
```

Der Dienst läuft als root, weil er `nmcli`, `firewall-cmd` und `systemctl` aufruft
und nach `/etc/firewalld` schreibt. Erreichbar ist er nur dort, wo Port 8090
freigegeben ist — ab Werk nur im Haupt-LAN. Ob ein VLAN zusätzlich darf,
entscheidet die Zugriffsmatrix unter „Anwendungen“.
