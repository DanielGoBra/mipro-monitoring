"""Red avanzada: ping con latencia, MAC por ARP, vendor OUI, tipo dispositivo.
Sin Npcap: usa ping + arp -a + sockets (100% Windows compatible).
scapy es opcional y solo se usa si está instalado.
"""
import socket
import subprocess
import platform
import ipaddress
import concurrent.futures
import re
import os

# --- OUI básico embebido (los más comunes en tu red) ---
OUI = {
    "00:23:24": "G-PRO COMPUTER", "00:1B:21": "Intel Corporate",
    "F4:70:18": "Hangzhou Ezviz Software Co.,Ltd.", "64:24:4D": "Hangzhou Ezviz Software Co.,Ltd.",
    "A0:FF:0C": "Hangzhou Hikvision Digital Technology Co.,Ltd.",
    "F0:61:C0": "Hewlett Packard Enterprise", "BC:24:11": "Proxmox Server Solutions GmbH",
    "6C:2B:59": "Dell Inc.", "D0:3C:1F": "Apple, Inc.", "F8:9E:94": "Apple, Inc.",
}

def _load_oui_db() -> dict:
    """Base IEEE de mac_vendor_lookup leída una vez a memoria (segura entre hilos)."""
    try:
        from mac_vendor_lookup import AsyncMacLookup
        db = {}
        with open(AsyncMacLookup.cache_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                pre, _, name = line.strip().partition(":")
                if len(pre) == 6 and name:
                    db[pre.upper()] = name
        return db
    except Exception:
        return {}

_OUI_DB = _load_oui_db()

def ping_latency(ip: str, timeout_ms=800):
    """Devuelve (alive: bool, ms: float|None). Parsea tiempo=XXms."""
    system = platform.system().lower()
    try:
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
        out = (res.stdout or "") + (res.stderr or "")
        if res.returncode != 0:
            # aunque falle, a veces hay respuesta; buscar tiempo=
            pass
        m = re.search(r"tiempo[=<]\s*(\d+)\s*ms", out, re.IGNORECASE)
        if not m:
            m = re.search(r"time[=<]\s*(\d+\.?\d*)\s*ms", out, re.IGNORECASE)
        ms = float(m.group(1)) if m else None
        alive = res.returncode == 0 or ms is not None
        return alive, ms
    except Exception:
        return False, None

def ping_once(ip: str, timeout_ms=800) -> bool:
    alive, _ = ping_latency(ip, timeout_ms)
    return alive

def check_port(ip: str, port: int, timeout=0.4):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.close()
        return True
    except Exception:
        return False

def resolve_name(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

# --- MAC via tabla ARP del sistema (rápido, sin Npcap) ---
_arp_cache = {}
def load_arp_table():
    global _arp_cache
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=8).stdout or ""
        # formatos: 192.168.1.1  00-23-24-c3-8e-e8  dinámico
        for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-:]{17})", out):
            ip = m.group(1)
            mac = m.group(2).replace("-", ":").lower()
            _arp_cache[ip] = mac
    except Exception:
        pass
    return _arp_cache

def get_mac(ip: str) -> str:
    if ip in _arp_cache:
        return _arp_cache[ip]
    load_arp_table()
    if ip in _arp_cache:
        return _arp_cache[ip]
    # fallback getmac lib
    try:
        from getmac import get_mac_address
        mac = get_mac_address(ip=ip) or ""
        if mac and mac != "00:00:00:00:00:00":
            return mac.lower()
    except Exception:
        pass
    return ""

def vendor_of(mac: str) -> str:
    if not mac or len(mac) < 8:
        return "Desconocido"
    mac = mac.lower()
    prefix = mac[:8].upper().replace("-", ":")
    v = _OUI_DB.get(re.sub(r"[^0-9A-F]", "", prefix))
    if v:
        return v
    if prefix in OUI:
        return OUI[prefix]
    if int(mac[1], 16) & 2:
        return "MAC aleatoria"
    return "Desconocido"

_ROLE_LABEL = {
    "gateway": "Router / Gateway",
    "firewall": "Firewall",
    "printer": "Impresora",
    "ap": "Access point",
    "switch": "Switch",
    "pc": "PC",
    "server": "Servidor",
    "camera": "Cámara / NVR",
    "mobile": "Móvil",
    "linux": "Linux",
    "unknown": "Desconocido",
}
_AP_VENDORS = ("ubiquiti", "unifi", "aruba", "ruckus", "cambium", "engenius", "aironet", "grandstream", "meraki")
_SW_VENDORS = ("cisco", "juniper", "mikrotik", "netgear", "d-link", "tp-link", "tplink", "hpe", "extreme", "zyxel", "allied", "aruba")
_PRINT_HINTS = ("print", "printer", "impresora", "canon", "epson", "brother", "lexmark", "xerox", "ricoh", "kyocera",
                "zebra", "konica", "sharp", "laserjet", "officejet", "deskjet", "pagewide", "imagerunner", "bizhub",
                "web image monitor", "embedded web server", "workcentre", "versalink", "ecosys", "taskalfa")
_PHONE_VENDORS = ("xiaomi", "samsung", "apple", "motorola", "huawei", "oppo", "vivo", "realme", "oneplus")
_PC_VENDORS = ("dell", "intel", "lenovo", "hewlett", "asus", "acer", "microsoft", "azurewave", "liteon", "realtek",
               "giga-byte", "micro-star", "hon hai", "foxconn", "quanta", "wistron", "compal", "pegatron")
_CAM_HINTS = ("hikvision", "dahua", "axis", "hanwha", "uniview", "ezviz", "network camera", "ip camera", "ipcam",
              "nvr", "dvr", "app-webs", "dnvrs-webs", "reolink", "amcrest", "milesight")
_AP_HINTS = ("unifi", "access point", "omada", "eap", "airos", "aruba instant", "instant on", "ruckus", "aironet",
             "meraki", "wireless ap")
_VM_VENDORS = ("proxmox", "vmware", "qemu", "xensource", "parallels", "hyper-v", "virtualbox")
_SW_HINTS = ("switch", "procurve", "smart managed", "jetstream", "prosafe", "catalyst", "edgeswitch", "sg300", "sg350",
             "cbs", "officeconnect", "bridge")
_FW_HINTS = ("fortinet", "fortigate", "palo alto", "pan-os", "sophos", "watchguard", "sonicwall", "pfsense", "opnsense", "checkpoint")
_ROUTER_HINTS = ("mikrotik", "routeros", "junos", "router", "edgerouter", "cisco ios", "ios xe", "vyos")
_SERVER_HINTS = ("microsoft-iis", "windows server", "vmware", "esxi", "proxmox", "synology", "qnap", "idrac", "ilo",
                 "apache", "nginx", "tomcat", "jetty")


def _has(text, words):
    return any(w in text for w in words)


def classify_role(ip: str, hostname: str, ports: list, vendor: str, mac: str = "",
                  hints: str = "", facts: dict = None, why: list = None) -> tuple:
    """Devuelve (rol, etiqueta) con lo ya observado. `why` recibe la evidencia en texto."""
    hn = (hostname or "").lower()
    v = (vendor or "").lower()
    h = (hints or "").lower()
    facts = facts or {}
    blob = hn + " " + v + " " + h
    ports = set(ports or [])
    mac = (mac or "").lower()
    why = why if why is not None else []
    last_octet = 0
    try:
        last_octet = int(str(ip).split(".")[-1])
    except Exception:
        pass

    def pack(role, reason):
        why.append(reason)
        return role, _ROLE_LABEL[role]

    if facts.get("printer_mib"):
        return pack("printer", "SNMP Printer-MIB responde")
    if ports & {9100, 515, 631}:
        return pack("printer", "Puerto de impresión " + ", ".join(str(p) for p in sorted(ports & {9100, 515, 631})))
    if _has(hn + " " + h, _PRINT_HINTS):
        return pack("printer", "Nombre o portada de impresora")
    if _has(blob, _FW_HINTS):
        return pack("firewall", "Firma de firewall")
    if _has(h + " " + v, _CAM_HINTS) or _has(hn, ("cam", "nvr", "dvr")):
        return pack("camera", "Portada o marca de cámara")
    if 554 in ports and not _has(v, _PC_VENDORS):
        return pack("camera", "RTSP 554 abierto")
    switch_name = bool(re.search(r"(switch|edgeswitch|usw)([^a-z0-9]|$)|(^|[^a-z0-9])sw[-_]", hn))
    ap_name = bool(re.search(r"(^|[^a-z0-9])(ap|uap|wap|unifi|aironet)([^a-z0-9]|$)", hn))
    if ap_name or _has(h, _AP_HINTS) or (_has(v, _AP_VENDORS) and not switch_name and not facts.get("bridge_ports")):
        return pack("ap", "Nombre, portada o marca de access point")
    if last_octet == 1 or _has(h, _ROUTER_HINTS) and not switch_name:
        return pack("gateway", "Primera IP del segmento" if last_octet == 1 else "Firma de router")
    if switch_name or _has(h, _SW_HINTS) or (facts.get("bridge_ports") or 0) > 4 \
            or (ports & {22, 23} and _has(v, _SW_VENDORS)):
        return pack("switch", "SNMP Bridge-MIB con %s puertos" % facts["bridge_ports"] if facts.get("bridge_ports") else "Nombre, portada o marca de switch")
    if 3389 in ports or ports & {445, 139} or _has(hn, ("iks-", "pc-", "lap-", "desktop", "laptop", "portatil")):
        return pack("pc", "Servicios de escritorio Windows")
    if _has(v, _VM_VENDORS):
        return pack("server", "Máquina virtual (" + vendor.split()[0] + ")")
    if _has(h, _SERVER_HINTS) or ports & {80, 443, 8080, 8000, 8443, 8001}:
        return pack("server", "Publica servicios web")
    if 22 in ports:
        return pack("linux", "Solo SSH abierto")
    if mac and int(mac[1], 16) & 2 or "random" in v or "aleatoria" in v or "virtual" in v or _has(v, _PHONE_VENDORS):
        return pack("mobile", "MAC aleatoria o marca de móvil")
    if _has(v, _PC_VENDORS):
        return pack("pc", "Marca de tarjeta de red de equipo")
    if not ports and not hn:
        return pack("mobile", "Sin servicios ni nombre")
    return pack("unknown", "Sin evidencia suficiente")


def classify_device(ip: str, hostname: str, ports: list, vendor: str, mac: str) -> str:
    return classify_role(ip, hostname, ports, vendor, mac)[1]

def probe_host(ip: str, ports, timeout=0.4):
    alive, ms = ping_latency(ip)
    open_ports = []
    # si ping ok o para detectar aunque ping bloqueado
    if alive:
        open_ports = [p for p in ports if check_port(ip, p, timeout)]
    else:
        open_ports = [p for p in ports if check_port(ip, p, timeout)]
        if open_ports:
            alive = True
            if ms is None:
                _, ms = ping_latency(ip)
    if not alive:
        return None
    mac = get_mac(ip)
    vendor = vendor_of(mac) if mac else "Desconocido"
    hn = resolve_name(ip)
    why = []
    role, dtype = classify_role(ip, hn, open_ports, vendor, mac, why=why)
    return {
        "ip": ip, "hostname": hn or "-", "mac": mac or "-",
        "vendor": vendor, "role": role, "device_type": dtype,
        "latency_ms": ms, "open_ports": open_ports, "online": True,
        "physical": None, "software": None, "advisories": [], "evidence": why,
    }


def _enrich(alive, communities, workers=32):
    """Portada web y SNMP de lectura sobre los equipos vivos; reclasifica con esa evidencia."""
    from . import fingerprint as fp
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        banners = dict(zip([h["ip"] for h in alive],
                           ex.map(lambda h: fp.http_banner(h["ip"], h["open_ports"]), alive)))
    pending = [h["ip"] for h in alive]
    snmp = {}
    for community in communities or ["public"]:
        if not pending:
            break
        deep = [h["ip"] for h in alive if h["ip"] in pending and h["role"] in ("switch", "gateway", "ap", "firewall")]
        got = fp.snmp_batch(pending, community=community, deep_ips=deep)
        for ip, data in got.items():
            data["community_ok"] = True
            snmp[ip] = data
        pending = [ip for ip in pending if ip not in got]
    for h in alive:
        ip = h["ip"]
        b = banners.get(ip)
        s = snmp.get(ip)
        hints = []
        if b:
            h["web"] = b
            hints += [b.get("title", ""), b.get("server", ""), b.get("realm", "")]
        facts = {}
        if s:
            descr = s.get("sysDescr")
            if isinstance(descr, bytes):
                descr = descr.decode("latin-1", "ignore")
            hints += [str(descr or ""), str(s.get("sysName") or ""), fp.enterprise_of(s.get("sysObjectID"))]
            facts["printer_mib"] = s.get("hrPrinterStatus") is not None or s.get("hrPrinterError") is not None
            facts["bridge_ports"] = s.get("bridgePorts") if isinstance(s.get("bridgePorts"), int) else 0
            if h.get("hostname") in ("-", "") and s.get("sysName"):
                h["hostname"] = str(s["sysName"])
            physical, software = fp.describe(s)
            h["physical"], h["software"] = physical, software
            if software and software.get("vendor") and h.get("vendor") in ("Desconocido", "MAC aleatoria"):
                h["vendor"] = software["vendor"]
            macs = fp.fdb_macs(s)
            if macs:
                h["fdb"] = macs
        why = []
        role, dtype = classify_role(ip, h.get("hostname"), h["open_ports"], h.get("vendor"), h.get("mac") if h.get("mac") != "-" else "",
                                    hints=" ".join(x for x in hints if x), facts=facts, why=why)
        if b and (b.get("title") or b.get("server")):
            why.append("Web: " + " · ".join(x for x in (b.get("title"), b.get("server")) if x)[:90])
        if s:
            why.append("SNMP: " + ((h.get("software") or {}).get("model") or "responde")[:90])
        h["role"], h["device_type"], h["evidence"] = role, dtype, why
        h["snmp"] = bool(s)
    return alive


def scan_subnet(cidr: str, ports=(80, 443, 3389, 22, 8080, 8443, 9100, 445), timeout=0.4, max_hosts=254, workers=64,
                communities=("public",), enrich=True):
    """Escaneo enriquecido con MAC, marca, tipo, portada web y SNMP de lectura."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        return {"error": str(e), "hosts": []}
    hosts = [str(ip) for ip in net.hosts()][:max_hosts]
    load_arp_table()
    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(probe_host, ip, ports, timeout): ip for ip in hosts}
        for f in concurrent.futures.as_completed(futs):
            try:
                r = f.result()
            except Exception:
                r = None
            if r:
                alive.append(r)
    alive.sort(key=lambda h: tuple(int(x) for x in h["ip"].split(".")))
    if enrich and alive:
        try:
            _enrich(alive, list(communities or ["public"]))
        except Exception as e:
            for h in alive:
                h.setdefault("evidence", []).append(f"Enriquecimiento omitido: {type(e).__name__}")
    for h in alive:
        h["subnet"] = cidr
    return {"subnet": cidr, "found": len(alive), "hosts": alive}

def live_ping_hosts(ips: list, timeout_ms=500, workers=64):
    """Re-ping rápido solo de IPs conocidas para tabla en vivo."""
    out = []
    def _one(ip):
        alive, ms = ping_latency(ip, timeout_ms)
        return {"ip": ip, "online": alive, "latency_ms": ms}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, max(8, len(ips)))) as ex:
        for r in ex.map(_one, ips):
            out.append(r)
    return out
