"""Identificación pasiva de equipos ya vivos: SNMP v2c de solo lectura y portada web.

SNMP usa pysnmp 7 (asyncio). Todo es GET/WALK de lectura; nada se escribe en los equipos.
"""
import asyncio
import re
import warnings

import requests

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

OID = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "bridgePorts": "1.3.6.1.2.1.17.1.2.0",
    "hrPrinterStatus": "1.3.6.1.2.1.25.3.5.1.1.1",
    "hrPrinterError": "1.3.6.1.2.1.25.3.5.1.2.1",
    "hrDeviceStatus": "1.3.6.1.2.1.25.3.2.1.5.1",
}
WALK = {
    "supplyName": "1.3.6.1.2.1.43.11.1.1.6",
    "supplyMax": "1.3.6.1.2.1.43.11.1.1.8",
    "supplyLevel": "1.3.6.1.2.1.43.11.1.1.9",
    "ifOper": "1.3.6.1.2.1.2.2.1.8",
    "ifType": "1.3.6.1.2.1.2.2.1.3",
    "fdbPort": "1.3.6.1.2.1.17.4.3.1.2",
    "qFdbPort": "1.3.6.1.2.1.17.7.1.2.2.1.2",
}

ENTERPRISE = {
    "9": "Cisco", "11": "HP", "171": "D-Link", "253": "Xerox", "367": "Ricoh", "641": "Lexmark",
    "1248": "Epson", "1347": "Kyocera", "1602": "Canon", "2435": "Brother", "2636": "Juniper",
    "4526": "Netgear", "11863": "TP-Link", "12356": "Fortinet", "14988": "MikroTik", "25461": "Palo Alto",
    "25053": "Ruckus", "14823": "Aruba", "41112": "Ubiquiti", "39165": "Hikvision", "1004849": "Dahua",
    "311": "Microsoft", "8072": "Net-SNMP", "674": "Dell", "2011": "Huawei", "3375": "F5", "18334": "Konica Minolta",
    "236": "Samsung", "10418": "Avocent", "6876": "VMware", "6027": "Force10", "47196": "Grandstream",
}

PRINTER_ERRORS = [
    "Poco papel", "Sin papel", "Poco tóner", "Sin tóner", "Tapa abierta", "Atasco",
    "Fuera de línea", "Requiere servicio", "Falta bandeja de entrada", "Falta bandeja de salida",
    "Falta consumible", "Bandeja de salida casi llena", "Bandeja de salida llena",
    "Bandeja de entrada vacía", "Mantenimiento vencido",
]
PRINTER_STATUS = {1: "Otro", 2: "Desconocido", 3: "En espera", 4: "Imprimiendo", 5: "Calentando"}
DEVICE_STATUS = {1: "Desconocido", 2: "Operativo", 3: "Advertencia", 4: "En prueba", 5: "Caído"}


def _pysnmp():
    try:
        from pysnmp.hlapi.v3arch.asyncio import (SnmpEngine, CommunityData, UdpTransportTarget,
                                                  ContextData, ObjectType, ObjectIdentity, get_cmd, walk_cmd)
        return SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity, get_cmd, walk_cmd
    except Exception:
        return None


def _val(v):
    try:
        cls = v.__class__.__name__
        if cls in ("NoSuchObject", "NoSuchInstance", "EndOfMibView"):
            return None
        if cls == "OctetString":
            raw = bytes(v)
            try:
                txt = raw.decode("utf-8")
                if txt.isprintable() or "\n" in txt or "\r" in txt:
                    return txt.strip()
            except Exception:
                pass
            return raw
        if cls == "ObjectIdentifier":
            return str(v)
        if cls in ("Integer", "Integer32", "Counter32", "Counter64", "Gauge32", "Unsigned32", "TimeTicks"):
            return int(v)
        return v.prettyPrint()
    except Exception:
        return None


async def _snmp_host(api, engine, ip, community, timeout, deep):
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity, get_cmd, walk_cmd = api
    try:
        target = await UdpTransportTarget.create((ip, 161), timeout=timeout, retries=0)
    except Exception:
        return None
    auth = CommunityData(community, mpModel=1)
    keys = list(OID.keys())
    try:
        err_ind, err_st, _, binds = await get_cmd(engine, auth, target, ContextData(),
                                                  *[ObjectType(ObjectIdentity(OID[k])) for k in keys[:5]])
    except Exception:
        return None
    if err_ind or err_st:
        return None
    out = {}
    for k, b in zip(keys[:5], binds):
        out[k] = _val(b[1])
    if not out.get("sysDescr") and not out.get("sysObjectID"):
        return None
    try:
        err_ind, err_st, _, binds = await get_cmd(engine, auth, target, ContextData(),
                                                  *[ObjectType(ObjectIdentity(OID[k])) for k in keys[5:]])
        if not err_ind and not err_st:
            for k, b in zip(keys[5:], binds):
                out[k] = _val(b[1])
    except Exception:
        pass

    async def walk(name, limit=400):
        rows = {}
        base = WALK[name]
        try:
            async for err_ind, err_st, _, binds in walk_cmd(engine, auth, target, ContextData(),
                                                            ObjectType(ObjectIdentity(base)),
                                                            lexicographicMode=False):
                if err_ind or err_st:
                    break
                for b in binds:
                    oid = str(b[0])
                    if not oid.startswith(base + "."):
                        return rows
                    rows[oid[len(base) + 1:]] = _val(b[1])
                if len(rows) >= limit:
                    break
        except Exception:
            pass
        return rows

    if out.get("hrPrinterStatus") is not None or out.get("hrPrinterError") is not None:
        out["supplies"] = {
            "name": await walk("supplyName", 40),
            "max": await walk("supplyMax", 40),
            "level": await walk("supplyLevel", 40),
        }
    if deep or (out.get("bridgePorts") or 0) > 4:
        out["ifOper"] = await walk("ifOper", 600)
        out["ifType"] = await walk("ifType", 600)
        fdb = await walk("fdbPort", 4000)
        if not fdb:
            fdb = await walk("qFdbPort", 4000)
        out["fdb"] = fdb
    return out


def snmp_batch(ips, community="public", timeout=1.2, deep_ips=()):
    """SNMP GET de identidad para varias IPs en paralelo. Devuelve {ip: dict}."""
    api = _pysnmp()
    if not api or not ips:
        return {}
    deep_ips = set(deep_ips or ())

    async def run():
        engine = api[0]()
        sem = asyncio.Semaphore(32)

        async def one(ip):
            async with sem:
                try:
                    return ip, await asyncio.wait_for(_snmp_host(api, engine, ip, community, timeout, ip in deep_ips), 25)
                except Exception:
                    return ip, None
        res = await asyncio.gather(*[one(ip) for ip in ips])
        try:
            engine.close_dispatcher()
        except Exception:
            pass
        return {ip: r for ip, r in res if r}

    try:
        return asyncio.run(run())
    except Exception:
        return {}


def http_banner(ip, ports):
    """Título y cabecera Server de la portada web (GET normal, como un navegador)."""
    for port in (80, 443, 8080, 8443, 8000):
        if port not in ports:
            continue
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{ip}:{port}/"
        try:
            first = _fetch(url)
        except Exception:
            continue
        if not first:
            continue
        loc = first.get("location") or ""
        if loc and re.match(r"^https?://" + re.escape(ip) + r"([:/]|$)", loc):
            try:
                nxt = _fetch(loc)
                if nxt and (nxt.get("title") or nxt.get("server")):
                    nxt["port"] = port
                    nxt["via"] = loc
                    nxt["server"] = nxt.get("server") or first.get("server", "")
                    return nxt
            except Exception:
                pass
        first["port"] = port
        return first
    return None


def _fetch(url):
    r = requests.get(url, timeout=1.8, verify=False, allow_redirects=False,
                     headers={"User-Agent": "MiPro-Inventario/1.0"})
    text = r.text[:20000] if "text" in (r.headers.get("content-type") or "text") else ""
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    title = re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""
    if re.fullmatch(r"\d{3}( [A-Za-z ]+)?", title):
        title = ""
    server = (r.headers.get("server") or "")[:80]
    realm = (r.headers.get("www-authenticate") or "")[:80]
    location = (r.headers.get("location") or "")[:160]
    if title or server or realm or location:
        return {"title": title, "server": server, "realm": realm, "location": location}
    return None


def enterprise_of(sys_oid):
    m = re.match(r"^1\.3\.6\.1\.4\.1\.(\d+)", str(sys_oid or ""))
    return ENTERPRISE.get(m.group(1), "") if m else ""


def _fmt_uptime(ticks):
    try:
        s = int(ticks) // 100
    except Exception:
        return ""
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    return f"{d} d {h} h" if d else f"{h} h {s // 60} min"


def _printer_errors(raw):
    if raw is None:
        return []
    if isinstance(raw, int):
        data = raw.to_bytes(max(1, (raw.bit_length() + 7) // 8), "big")
    elif isinstance(raw, bytes):
        data = raw
    else:
        data = str(raw).encode("latin-1", "ignore")
    alerts = []
    for byte_i, byte in enumerate(data[:2]):
        for bit in range(8):
            if byte & (0x80 >> bit):
                idx = byte_i * 8 + bit
                if idx < len(PRINTER_ERRORS):
                    alerts.append(PRINTER_ERRORS[idx])
    return alerts


def _supplies(sup):
    rows = []
    if not sup:
        return rows
    names, maxs, levels = sup.get("name", {}), sup.get("max", {}), sup.get("level", {})
    for idx, name in names.items():
        if isinstance(name, bytes):
            name = name.decode("latin-1", "ignore")
        mx, lv = maxs.get(idx), levels.get(idx)
        pct = None
        if isinstance(mx, int) and isinstance(lv, int):
            if mx > 0 and lv >= 0:
                pct = max(0, min(100, round(lv * 100 / mx)))
            elif lv == -3:
                pct = 100
        rows.append({"name": str(name)[:60], "pct": pct})
    return rows[:12]


def describe(snmp):
    """Traduce la lectura SNMP a los bloques físico y software del dossier."""
    if not snmp:
        return None, None
    descr = snmp.get("sysDescr")
    if isinstance(descr, bytes):
        descr = descr.decode("latin-1", "ignore")
    descr = (descr or "").strip()
    brand = enterprise_of(snmp.get("sysObjectID"))
    fw = ""
    m = re.search(r"(?:version|firmware|fw|ver\.?|v)\s*[:=]?\s*([0-9][\w.\-()]{1,30})", descr, re.IGNORECASE)
    if m:
        fw = m.group(1)
    software = {
        "model": (descr.split(",")[0] if descr else "")[:90] or brand,
        "firmware": fw,
        "vendor": brand,
        "sys_name": snmp.get("sysName") or "",
        "location": snmp.get("sysLocation") or "",
        "descr": descr[:240],
        "source": "SNMP",
    }
    physical = {"uptime": _fmt_uptime(snmp.get("sysUpTime")), "source": "SNMP"}
    alerts = []
    if snmp.get("hrPrinterStatus") is not None or snmp.get("hrPrinterError") is not None:
        st = PRINTER_STATUS.get(snmp.get("hrPrinterStatus"), "Sin dato")
        dev = DEVICE_STATUS.get(snmp.get("hrDeviceStatus"), "")
        alerts = _printer_errors(snmp.get("hrPrinterError"))
        sup = _supplies(snmp.get("supplies"))
        low = [s for s in sup if s["pct"] is not None and s["pct"] <= 15]
        for s in low:
            alerts.append(f"{s['name']} al {s['pct']} %")
        physical.update({"kind": "printer", "status": st, "device": dev, "supplies": sup})
        state = "fail" if any(a in alerts for a in ("Sin papel", "Sin tóner", "Atasco", "Tapa abierta", "Fuera de línea")) or dev == "Caído" \
            else "warn" if alerts or dev == "Advertencia" else "ok"
        physical["state"] = state
        physical["summary"] = f"{st}" + (f" · {', '.join(alerts[:3])}" if alerts else " · sin alertas")
    elif snmp.get("ifOper"):
        types = snmp.get("ifType") or {}
        eth = [i for i, t in types.items() if t in (6, 117, 62, 69)] or list(snmp["ifOper"].keys())
        up = sum(1 for i in eth if snmp["ifOper"].get(i) == 1)
        down = sum(1 for i in eth if snmp["ifOper"].get(i) == 2)
        physical.update({"kind": "switch", "ports_up": up, "ports_down": down, "ports_total": len(eth),
                         "summary": f"{up} puertos arriba de {len(eth)}", "state": "ok"})
    else:
        physical.update({"kind": "generic", "state": "ok",
                         "summary": f"Responde SNMP · encendido {physical['uptime']}" if physical["uptime"] else "Responde SNMP"})
    physical["alerts"] = alerts
    return physical, software


def fdb_macs(snmp):
    """{mac: puerto} desde la tabla de reenvío del switch."""
    out = {}
    for idx, port in (snmp or {}).get("fdb", {}).items():
        parts = idx.split(".")[-6:]
        if len(parts) != 6 or not isinstance(port, int) or port <= 0:
            continue
        try:
            mac = ":".join(f"{int(x):02x}" for x in parts)
        except ValueError:
            continue
        out[mac] = port
    return out
