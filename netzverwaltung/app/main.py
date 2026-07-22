"""Netzverwaltung -- Weboberflaeche fuer DHCP und Routing des Unterrichtsnetzes.

Deckt bewusst nur das ab, was Cockpit nicht kann: DHCP-Vergabe, die
Zugriffsmatrix zwischen den VLANs und das Anlegen neuer VLANs. Interfaces,
Routen, Dienste und Logs bleiben in Cockpit auf Port 9090.
"""
from __future__ import annotations

import ipaddress
import subprocess
import time
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import applier, auth, config, importer, leases, store
from .model import Access, Dhcp, DnsFilter, Reservation, ValidationError, Vlan, validate

BASE = Path(__file__).parent
app = FastAPI(title="Netzverwaltung", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")


# --- Rahmen -----------------------------------------------------------------

def page(request: Request, name: str, **ctx) -> HTMLResponse:
    state = ctx.pop("state", None) or store.load()
    ctx.setdefault("state", state)
    ctx.setdefault("pending", applier.pending())
    ctx.setdefault("dirty", bool(applier.diff(state)))
    ctx.setdefault("csrf", auth.csrf_token(request))
    ctx.setdefault("config", config)
    return templates.TemplateResponse(request, name, ctx)


def redirect(path: str, note: str = "", error: str = "") -> RedirectResponse:
    query = []
    if note:
        query.append(f"note={note}")
    if error:
        query.append(f"error={error}")
    sep = "?" if query else ""
    return RedirectResponse(f"{path}{sep}{'&'.join(query)}", status_code=303)


@app.middleware("http")
async def guard(request: Request, call_next):
    """Anmeldepflicht und CSRF-Schutz an einer Stelle."""
    path = request.url.path
    if path.startswith("/static") or path in ("/login", "/setup"):
        return await call_next(request)

    if not auth.password_is_set():
        return RedirectResponse("/setup", status_code=303)
    if not auth.is_authenticated(request):
        return RedirectResponse("/login", status_code=303)

    if request.method == "POST":
        form = await request.form()
        if not auth.csrf_ok(request, form.get("csrf", "")):
            return HTMLResponse("Sitzung abgelaufen. Bitte neu anmelden.", status_code=403)
        request.state.form = form

    return await call_next(request)


async def form_data(request: Request):
    return getattr(request.state, "form", None) or await request.form()


# --- Anmeldung --------------------------------------------------------------

@app.get("/setup", response_class=HTMLResponse)
def setup_form(request: Request):
    if auth.password_is_set():
        return redirect("/login")
    return templates.TemplateResponse(request, "setup.html", {"error": ""})


@app.post("/setup")
def setup_save(request: Request, password: str = Form(...), password2: str = Form(...)):
    if auth.password_is_set():
        return redirect("/login")
    if password != password2:
        return templates.TemplateResponse(
            request, "setup.html", {"error": "Die beiden Passwoerter stimmen nicht ueberein."})
    try:
        auth.set_password(password)
    except ValueError as exc:
        return templates.TemplateResponse(request, "setup.html", {"error": str(exc)})
    return redirect("/login")


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if not auth.password_is_set():
        return redirect("/setup")
    return templates.TemplateResponse(request, "login.html", {"error": ""})


@app.post("/login")
def login(request: Request, password: str = Form(...)):
    if not auth.check_password(password):
        time.sleep(1)  # bremst Rateversuche
        return templates.TemplateResponse(
            request, "login.html", {"error": "Passwort falsch."}, status_code=401)
    response = redirect("/")
    response.set_cookie(
        auth.COOKIE, auth.issue_session(),
        httponly=True, samesite="strict", max_age=auth.SESSION_HOURS * 3600,
    )
    return response


@app.post("/logout")
def logout():
    response = redirect("/login")
    response.delete_cookie(auth.COOKIE)
    return response


# --- Uebersicht -------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def overview(request: Request, note: str = "", error: str = ""):
    state = store.load()
    active = leases.read(state)
    counts = {v.name: sum(1 for l in active if l.vlan == v.name) for v in state.vlans}
    return page(request, "overview.html", state=state, counts=counts,
                total_leases=len(active), services=_service_status(),
                note=note, error=error)


def _service_status() -> list[dict]:
    out = []
    for unit, label in [("dnsmasq", "DHCP/DNS"), ("firewalld", "Firewall"),
                        ("NetworkManager", "Netzwerk"), ("dnsmasq-filter", "DNS-Filter")]:
        proc = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True)
        out.append({"unit": unit, "label": label, "state": proc.stdout.strip()})
    return out


# --- VLANs ------------------------------------------------------------------

@app.get("/vlans", response_class=HTMLResponse)
def vlan_list(request: Request, note: str = "", error: str = ""):
    return page(request, "vlans.html", note=note, error=error)


@app.get("/vlans/neu", response_class=HTMLResponse)
def vlan_new(request: Request):
    state = store.load()
    return page(request, "vlan_form.html", state=state, vlan=None,
                suggestion=_suggest_vlan(state), error="")


def _suggest_vlan(state) -> dict:
    """Naechste freie VLAN-ID und ein dazu passendes, noch unbenutztes /24."""
    used_ids = {v.vlan_id for v in state.vlans}
    vlan_id = next(i for i in range(10, 4095, 10) if i not in used_ids)
    used_nets = [v.network for v in state.vlans]
    for third in range(10, 255):
        candidate = ipaddress.ip_network(f"192.168.{third}.0/24")
        if any(candidate.overlaps(n) for n in used_nets):
            continue
        if candidate.overlaps(ipaddress.ip_network(config.LAN_SUBNET)):
            continue
        return {"vlan_id": vlan_id, "address": f"192.168.{third}.1/24",
                "start": f"192.168.{third}.50", "end": f"192.168.{third}.250"}
    return {"vlan_id": vlan_id, "address": "", "start": "", "end": ""}


@app.post("/vlans/neu")
async def vlan_create(request: Request):
    form = await form_data(request)
    state = store.load()
    try:
        vlan = _vlan_from_form(form)
        state.vlans.append(vlan)
        validate(state)
        store.save(state)
    except ValidationError as exc:
        return page(request, "vlan_form.html", state=store.load(), vlan=None,
                    suggestion=_suggest_vlan(store.load()),
                    error="<br>".join(exc.problems))
    except (ValueError, KeyError) as exc:
        return page(request, "vlan_form.html", state=store.load(), vlan=None,
                    suggestion=_suggest_vlan(store.load()), error=str(exc))
    return redirect("/aenderungen", note=f"VLAN+{vlan.name}+angelegt")


@app.get("/vlans/{name}", response_class=HTMLResponse)
def vlan_edit(request: Request, name: str):
    state = store.load()
    vlan = state.get(name)
    if not vlan:
        return redirect("/vlans", error="VLAN+nicht+gefunden")
    return page(request, "vlan_form.html", state=state, vlan=vlan,
                suggestion=None, error="")


@app.post("/vlans/{name}")
async def vlan_save(request: Request, name: str):
    form = await form_data(request)
    state = store.load()
    vlan = state.get(name)
    if not vlan:
        return redirect("/vlans", error="VLAN+nicht+gefunden")

    updated = _vlan_from_form(form, keep=vlan)
    state.vlans = [updated if v.name == name else v for v in state.vlans]
    try:
        store.save(state)
    except ValidationError as exc:
        return page(request, "vlan_form.html", state=store.load(),
                    vlan=updated, suggestion=None, error="<br>".join(exc.problems))
    return redirect("/aenderungen", note=f"VLAN+{name}+geaendert")


@app.post("/vlans/{name}/loeschen")
def vlan_delete(request: Request, name: str):
    state = store.load()
    state.vlans = [v for v in state.vlans if v.name != name]
    # Verweise aus der Matrix mitnehmen, sonst schlaegt die Validierung fehl.
    for v in state.vlans:
        v.access.vlans = [p for p in v.access.vlans if p != name]
    store.save(state)
    return redirect("/aenderungen", note=f"VLAN+{name}+entfernt")


def _vlan_from_form(form, keep: Vlan | None = None) -> Vlan:
    name = (form.get("name") or "").strip().lower()
    return Vlan(
        name=name,
        vlan_id=int(form.get("vlan_id") or 0),
        address=(form.get("address") or "").strip(),
        description=(form.get("description") or "").strip(),
        parent=(form.get("parent") or config.VLAN_PARENT).strip(),
        dhcp=Dhcp(
            enabled=form.get("dhcp_enabled") == "on",
            start=(form.get("dhcp_start") or "").strip(),
            end=(form.get("dhcp_end") or "").strip(),
            lease=(form.get("dhcp_lease") or "12h").strip(),
        ),
        reservations=keep.reservations if keep else [],
        access=keep.access if keep else Access(services=["dhcp", "dns"]),
        dns_filter=keep.dns_filter if keep else DnsFilter(),
    )


# --- Leases und Reservierungen ---------------------------------------------

@app.get("/leases", response_class=HTMLResponse)
def lease_list(request: Request, note: str = "", error: str = ""):
    state = store.load()
    return page(request, "leases.html", state=state, leases=leases.read(state),
                reserved=leases.reserved_macs(state), note=note, error=error)


@app.post("/leases/reservieren")
async def lease_reserve(request: Request):
    form = await form_data(request)
    state = store.load()
    vlan = state.get(form.get("vlan") or "")
    if not vlan:
        return redirect("/leases", error="Unbekanntes+VLAN")

    mac = (form.get("mac") or "").lower()
    ip = (form.get("ip") or "").strip() or leases.suggest_ip(state, vlan.name)
    hostname = (form.get("hostname") or "").strip()
    if hostname in ("*", "—"):
        hostname = ""

    vlan.reservations = [r for r in vlan.reservations if r.mac != mac]
    vlan.reservations.append(Reservation(mac=mac, ip=ip, name=hostname))
    vlan.reservations.sort(key=lambda r: ipaddress.ip_address(r.ip) if r.ip else 0)
    try:
        store.save(state)
    except ValidationError as exc:
        return redirect("/leases", error="+".join(exc.problems[0].split()))
    return redirect("/aenderungen", note=f"Reservierung+{ip}+angelegt")


@app.post("/leases/freigeben")
async def lease_release(request: Request):
    form = await form_data(request)
    mac = (form.get("mac") or "").lower()
    state = store.load()
    for vlan in state.vlans:
        vlan.reservations = [r for r in vlan.reservations if r.mac != mac]
    store.save(state)
    return redirect("/aenderungen", note="Reservierung+entfernt")


# --- Zugriffsmatrix ---------------------------------------------------------

@app.get("/matrix", response_class=HTMLResponse)
def matrix(request: Request, note: str = "", error: str = ""):
    return page(request, "matrix.html", note=note, error=error)


@app.post("/matrix")
async def matrix_save(request: Request):
    form = await form_data(request)
    state = store.load()
    for vlan in state.vlans:
        n = vlan.name
        vlan.access.internet = form.get(f"internet:{n}") == "on"
        vlan.access.haupt_lan = form.get(f"lan:{n}") == "on"
        vlan.access.switch_gui = form.get(f"switch:{n}") == "on"
        vlan.access.vlans = [
            other.name for other in state.vlans
            if other.name != n and form.get(f"peer:{n}:{other.name}") == "on"
        ]
        vlan.access.services = [
            svc for svc, _ in config.HOST_SERVICES if form.get(f"svc:{n}:{svc}") == "on"
        ]
        vlan.access.ports = [
            port for port, _ in config.HOST_PORTS if form.get(f"port:{n}:{port}") == "on"
        ]
    try:
        store.save(state)
    except ValidationError as exc:
        return page(request, "matrix.html", state=state, error="<br>".join(exc.problems), note="")
    return redirect("/aenderungen", note="Zugriffsmatrix+geaendert")


# --- DNS-Filter -------------------------------------------------------------

@app.get("/filter", response_class=HTMLResponse)
def dns_filter(request: Request, note: str = "", error: str = ""):
    return page(request, "filter.html", note=note, error=error)


@app.post("/filter")
async def dns_filter_save(request: Request):
    form = await form_data(request)
    state = store.load()
    for vlan in state.vlans:
        n = vlan.name
        vlan.dns_filter = DnsFilter(
            enabled=form.get(f"filter:{n}") == "on",
            lists=[l for l in (form.get(f"lists:{n}") or "").split(",") if l],
            block=_domains(form.get(f"block:{n}")),
            allow=_domains(form.get(f"allow:{n}")),
        )
    store.save(state)
    return redirect("/aenderungen", note="DNS-Filter+geaendert")


def _domains(raw: str | None) -> list[str]:
    out = []
    for line in (raw or "").replace(",", "\n").splitlines():
        domain = line.strip().lower().lstrip(".")
        if domain and not domain.startswith("#"):
            out.append(domain)
    return sorted(set(out))


# --- Anwenden ---------------------------------------------------------------

@app.get("/aenderungen", response_class=HTMLResponse)
def changes(request: Request, note: str = "", error: str = ""):
    state = store.load()
    return page(request, "changes.html", state=state,
                changes=applier.diff(state), note=note, error=error)


@app.post("/anwenden")
def apply_changes(request: Request):
    state = store.load()
    try:
        result = applier.apply(state)
    except applier.ApplyError as exc:
        return redirect("/aenderungen", error="+".join(str(exc).split()))
    return redirect("/bestaetigen", note=str(int(result["deadline"])))


@app.get("/bestaetigen", response_class=HTMLResponse)
def confirm_page(request: Request, note: str = ""):
    info = applier.pending()
    if not info:
        return redirect("/", note="Aenderungen+aktiv")
    return page(request, "confirm.html", deadline=info["deadline"],
                remaining=int(info["deadline"] - time.time()), note="")


@app.post("/bestaetigen")
def confirm(request: Request):
    applier.confirm()
    return redirect("/", note="Aenderungen+bestaetigt")


# --- Import -----------------------------------------------------------------

@app.get("/import", response_class=HTMLResponse)
def import_page(request: Request, note: str = "", error: str = ""):
    detected, notes = importer.import_system()
    doomed_conf, conf_warnings = importer.obsolete_dnsmasq_files(detected)
    obsolete = importer.obsolete_policies(detected) + [p.name for p in doomed_conf]
    return page(request, "import.html", detected=detected, notes=notes + conf_warnings,
                obsolete=obsolete, note=note, error=error)


@app.post("/import")
def import_apply(request: Request):
    detected, _ = importer.import_system()
    try:
        store.save(detected)
    except ValidationError as exc:
        return redirect("/import", error="+".join(exc.problems[0].split()))
    return redirect("/aenderungen", note="Ist-Zustand+uebernommen")
