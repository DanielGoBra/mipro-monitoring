"""MiPro Monitoring v3 - maestra tiempo real + seguridad de red."""
import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from apscheduler.schedulers.background import BackgroundScheduler
from contextlib import asynccontextmanager
import os

from .database import (init_db, save_check, save_system, save_live, last_status, history,
                         system_history, live_history, incident_open, incident_resolve,
                         incident_ack, incidents_list, sla_stats)
from .monitor import ops as ops
from .config import load_config
from .monitor.http_check import check_target
from .monitor.system import get_system
from .monitor.livestats import get_live_snapshot, get_bandwidth_mbps, dns_probe
from .monitor.automations import check_automation
from .monitor.network import scan_subnet, live_ping_hosts
from .monitor import topology as topo
from .monitor.headers import audit_headers
from .monitor import security as sec

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
STATIC_DIR = os.path.join(BASE_DIR, "static")

latest_cache = {"http": [], "automations": [], "system": {}, "live": {}, "devices": [], "headers": [], "faults": []}
devices_cache = {"subnet": "", "hosts": []}
scanned_nets: dict = {}
ws_clients: set[WebSocket] = set()

def push_async(msg: dict):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(_broadcast(msg), loop)
    except Exception:
        pass

async def _broadcast(msg: dict):
    dead = []
    for ws in list(ws_clients):
        try:
            await ws.send_json(msg)
        except Exception:
            dead.append(ws)
    for d in dead:
        ws_clients.discard(d)

def job_http():
    cfg = load_config()
    results = []
    for t in cfg.get("http_targets", []):
        r = check_target(t)
        save_check("http", r["name"], r["ok"], r["latency_ms"], r["status_code"], r["detail"])
        results.append(r)
    latest_cache["http"] = results
    faults = sec.diagnose_faults(latest_cache.get("live"), results, devices_cache.get("hosts", []))
    latest_cache["faults"] = faults
    # incidentes persistentes: abrir por falla, resolver las que ya no están críticas
    try:
        crit_keys = set()
        for f in faults:
            if f.get("nivel") == "CRITICO":
                key = (f.get("msg") or "")[:80]
                crit_keys.add(key)
                incident_open(key, f.get("msg", "")[:140], f.get("nivel", ""), f.get("msg", ""))
        for inc in incidents_list(status="open", limit=50) + incidents_list(status="ack", limit=50):
            if inc["key"] not in crit_keys:
                incident_resolve(inc["key"])
        latest_cache["incidents"] = incidents_list(limit=20)
        push_async({"type": "incidents", "data": latest_cache["incidents"]})
    except Exception as e:
        print("incidents sync:", e)
    push_async({"type": "http", "data": results})
    push_async({"type": "faults", "data": latest_cache["faults"]})

def job_system():
    try:
        s = get_system()
        down, up = get_bandwidth_mbps()
        s["down_mbps"] = down
        s["up_mbps"] = up
        save_system(s["cpu"], s["ram"], s["disk"], s["net_sent_mb"], s["net_recv_mb"])
        latest_cache["system"] = s
        push_async({"type": "system", "data": s})
    except Exception as e:
        print("system error:", e)

def job_live():
    try:
        cfg = load_config()
        lp = cfg.get("live_ping", {})
        snap = get_live_snapshot(
            lp.get("gateway", "192.168.1.1"),
            lp.get("internet", "8.8.8.8"),
            lp.get("app_host", "inklusivapp.inklusiva.co"),
        )
        sys = latest_cache.get("system", {})
        save_live(snap["down_mbps"], snap["up_mbps"],
                  snap["ping_gateway_ms"], snap["ping_internet_ms"], snap["ping_app_ms"],
                  sys.get("cpu", 0), sys.get("ram", 0))
        latest_cache["live"] = snap
        push_async({"type": "live", "data": snap})
    except Exception as e:
        print("live error:", e)

def job_automations():
    cfg = load_config()
    results = []
    for a in cfg.get("automations", []):
        r = check_automation(a)
        save_check("automation", r["name"], r["ok"], r.get("latency_ms"), r.get("status_code"), r.get("detail", ""))
        results.append(r)
    latest_cache["automations"] = results
    push_async({"type": "automations", "data": results})

def job_devices_live():
    if not devices_cache.get("hosts"):
        return
    ips = [h["ip"] for h in devices_cache["hosts"]]
    live = {x["ip"]: x for x in live_ping_hosts(ips)}
    for h in devices_cache["hosts"]:
        lv = live.get(h["ip"])
        if lv:
            h["online"] = lv["online"]
            h["latency_ms"] = lv["latency_ms"]
    latest_cache["devices"] = devices_cache["hosts"]
    push_async({"type": "devices", "data": devices_cache["hosts"]})

def job_headers():
    cfg = load_config()
    out = []
    for t in cfg.get("http_targets", []):
        url = t.get("url")
        if not url or url.startswith("tcp://"):
            continue  # servicios TCP no tienen headers web que auditar
        a = audit_headers(url, timeout=int(t.get("timeout", 15)), verify_ssl=t.get("verify_ssl", True))
        a["name"] = t.get("name", url)
        save_check("headers", a["name"], a["ok"], a["latency_ms"], a.get("status_code"), f"score {a['score']}: {'; '.join(a['issues'][:2])}" if a["issues"] else f"score {a['score']} OK")
        out.append(a)
    latest_cache["headers"] = out
    push_async({"type": "headers", "data": out})

scheduler = BackgroundScheduler()

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    cfg = load_config(force=True)
    iv = cfg.get("check_intervals", {})
    scheduler.add_job(job_http, "interval", seconds=int(iv.get("http_seconds", 20)), id="http", max_instances=1)
    scheduler.add_job(job_system, "interval", seconds=int(iv.get("system_seconds", 3)), id="sys", max_instances=1)
    scheduler.add_job(job_live, "interval", seconds=int(iv.get("live_seconds", 5)), id="live", max_instances=1)
    scheduler.add_job(job_automations, "interval", seconds=int(iv.get("automation_seconds", 60)), id="auto", max_instances=1)
    scheduler.add_job(job_devices_live, "interval", seconds=int(iv.get("devices_live_seconds", 15)), id="devlive", max_instances=1)
    scheduler.add_job(job_headers, "interval", seconds=int(iv.get("headers_seconds", 600)), id="hdrs", max_instances=1)
    scheduler.start()
    for jid, fn in [("h0", job_http), ("s0", job_system), ("l0", job_live), ("a0", job_automations), ("hd0", job_headers)]:
        try:
            scheduler.add_job(fn, id=jid)
        except Exception:
            pass
    yield
    scheduler.shutdown()

app = FastAPI(title="MiPro Monitoring v3", lifespan=lifespan)

@app.get("/api/status")
def api_status():
    return {"last": last_status(), "cache": latest_cache, "devices": devices_cache}

@app.get("/api/history")
def api_history(name: str = "", hours: int = 6):
    return history(name or None, hours=hours)

@app.get("/api/system/history")
def api_system_history(hours: int = 6):
    return system_history(hours=hours)

@app.get("/api/live/history")
def api_live_history(hours: int = 2):
    hours = max(1, min(int(hours), 48))
    rows = live_history(hours=hours, limit=20000)
    if len(rows) > 240:
        step = max(1, len(rows) // 240)
        rows = rows[::step]
    return rows

@app.get("/api/live")
def api_live():
    return latest_cache.get("live", {})

@app.get("/api/config")
def api_config():
    return load_config()

@app.get("/api/network/scan")
def api_scan(cidr: str = "192.168.1.0/24"):
    global devices_cache
    cfg = load_config()
    net_cfg = cfg.get("network", {}) or {}
    ports = net_cfg.get("ports", [80, 443])
    timeout = float(net_cfg.get("timeout", 0.4))
    communities = net_cfg.get("snmp_communities") or ["public"]
    res = scan_subnet(cidr, ports=ports, timeout=timeout, communities=communities)
    if "hosts" in res:
        devices_cache = {"subnet": cidr, "hosts": res["hosts"]}
        scanned_nets[cidr] = res["hosts"]
        latest_cache["devices"] = res["hosts"]
        push_async({"type": "devices", "data": res["hosts"]})
    return res

@app.get("/api/network/topology")
def api_topology():
    """Diagrama con todos los segmentos escaneados en esta sesión del servidor."""
    nets = dict(scanned_nets)
    if devices_cache.get("subnet") and devices_cache["subnet"] not in nets:
        nets[devices_cache["subnet"]] = devices_cache.get("hosts", [])
    return topo.build(nets)

@app.delete("/api/network/topology")
def api_topology_forget(cidr: str):
    scanned_nets.pop(cidr, None)
    return {"ok": True, "subnets": list(scanned_nets.keys())}

@app.get("/api/network/dns")
def api_dns():
    """Resolución de los hostnames ya configurados (web, app, gateway)."""
    cfg = load_config()
    names = []
    app_host = (cfg.get("live_ping") or {}).get("app_host")
    if app_host:
        names.append(app_host)
    for t in cfg.get("http_targets", []):
        url = str(t.get("url") or "")
        if "://" not in url:
            continue
        host = url.split("://", 1)[1].split("/")[0].split(":")[0]
        names.append(host)
    return {"rows": dns_probe(names)}

@app.get("/api/network/live")
def api_net_live(cidr: str = ""):
    global devices_cache
    if devices_cache.get("hosts") and (not cidr or cidr == devices_cache.get("subnet")):
        job_devices_live()
        return {"subnet": devices_cache["subnet"], "found": len(devices_cache["hosts"]),
                "hosts": devices_cache["hosts"], "live": True}
    return api_scan(cidr or "192.168.1.0/24")

@app.get("/api/headers/audit")
def api_headers_audit(url: str):
    return audit_headers(url)

@app.get("/api/headers/status")
def api_headers_status():
    if not latest_cache.get("headers"):
        job_headers()
    return latest_cache.get("headers", [])

@app.get("/api/security/connections")
def api_connections():
    return sec.connections_snapshot()

@app.get("/api/security/insecure")
def api_insecure():
    return sec.insecure_browsing()

@app.get("/api/security/sniff")
def api_sniff(seconds: int = 8):
    seconds = max(3, min(30, seconds))
    return sec.scapy_sniff(seconds=seconds)

@app.get("/api/security/libraries")
def api_libs():
    from .monitor import cyber10 as c10
    libs = sec.libraries_status()
    libs.update(c10.libraries10())
    return {"libraries": libs, "pyshark": sec.pyshark_check(),
            "netmiko": sec.netmiko_facts((load_config().get("network"))),
            "napalm": sec.napalm_facts((load_config().get("network"))),
            "volatility": c10.volatility_status()}

@app.get("/api/cyber/nmap")
def api_nmap(target: str = "192.168.1.1", ports: str = "80,443,22,3389,8080,8443"):
    from .monitor import cyber10 as c10
    return c10.nmap_scan(target, ports)

@app.get("/api/cyber/page-intel")
def api_page_intel(url: str = "https://inklusiva.co/"):
    from .monitor import cyber10 as c10
    return c10.page_intel(url)

@app.get("/api/cyber/ssh-audit")
def api_ssh_audit(host: str = "192.168.1.1", port: int = 22):
    from .monitor import cyber10 as c10
    return c10.ssh_audit(host, port)

@app.get("/api/cyber/cert")
def api_cert(host: str = "inklusiva.co", port: int = 443):
    from .monitor import cyber10 as c10
    return c10.cert_deep(host, port)

@app.get("/api/cyber/shodan")
def api_shodan(ip: str = "8.8.8.8"):
    from .monitor import cyber10 as c10
    cfg = load_config()
    key = (cfg.get("shodan_api_key") or "")
    return c10.shodan_lookup(ip, key)

@app.get("/api/cyber/process-audit")
def api_proc_audit():
    from .monitor import cyber10 as c10
    return c10.process_audit()

@app.get("/api/incidents")
def api_incidents(status: str = "", limit: int = 50):
    return incidents_list(status=status or "", limit=min(limit, 200))

@app.post("/api/incidents/ack")
def api_inc_ack(id: int, by: str = "soporte"):
    incident_ack(id, by)
    latest_cache["incidents"] = incidents_list(limit=20)
    return {"ok": True}

@app.get("/api/sla")
def api_sla(days: int = 30):
    return sla_stats(days=max(1, min(days, 90)))

@app.get("/api/snmp/interfaces")
def api_snmp(host: str = "192.168.1.1", community: str = "public"):
    return ops.snmp_interfaces(host, community)

@app.get("/api/report.pdf")
def api_report(days: int = 7):
    import tempfile
    path = os.path.join(tempfile.gettempdir(), f"mipro_reporte_{days}d.pdf")
    r = ops.build_pdf(path, days=max(1, min(days, 90)))
    if "error" in r:
        return r
    return FileResponse(path, media_type="application/pdf", filename=f"mipro_reporte_{days}d.pdf")

@app.get("/api/faults")
def api_faults():
    f = sec.diagnose_faults(latest_cache.get("live"), latest_cache.get("http", []), devices_cache.get("hosts", []))
    latest_cache["faults"] = f
    return f

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    ws_clients.add(ws)
    try:
        await ws.send_json({"type": "init", "data": latest_cache})
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        ws_clients.discard(ws)

if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
def index():
    idx = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(idx):
        return FileResponse(idx)
    return {"msg": "Falta static/index.html"}

@app.get("/login")
def login_page():
    idx = os.path.join(STATIC_DIR, "login.html")
    if os.path.exists(idx):
        return FileResponse(idx)
    return {"msg": "Falta static/login.html"}

@app.get("/estado")
def estado():
    """Status page pública para usuarios (sin datos sensibles)."""
    idx = os.path.join(STATIC_DIR, "estado.html")
    if os.path.exists(idx):
        return FileResponse(idx)
    return {"msg": "Falta static/estado.html"}

@app.get("/api/public-status")
def api_public_status():
    """Resumen público: solo servicios web + uptime, sin red interna."""
    pub = []
    for h in latest_cache.get("http", []):
        if h.get("name", "").startswith("⭐"):
            continue  # infraestructura interna no pública
        pub.append({"name": h["name"], "ok": h["ok"], "latency_ms": h.get("latency_ms")})
    return {"services": pub, "incidents": [i for i in incidents_list(limit=10) if i["status"] != "resolved"]}
