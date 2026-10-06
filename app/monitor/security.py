"""Centro de seguridad y diagnóstico de red.
Integra las 5 librerías maestras con degradación elegante:
- Scapy: sniffing / conteo por IP / detección port-scan (requiere Npcap + admin)
- pyshark: análisis estilo Wireshark vía tshark (si está instalado)
- psutil: conexiones activas + top talkers (siempre disponible)
- Netmiko: SSH a router/switch Cisco/Juniper/HP (si hay credenciales en config)
- NAPALM: facts unificados multivendor (si hay credenciales)
Además: detección de navegación extraña, paquetes raros y fallos de red.
"""
import time
import socket
import collections
import os
import psutil

for _d in (r"C:\Program Files\Wireshark", r"C:\Program Files (x86)\Nmap", r"C:\Program Files\Nmap"):
    if os.path.isdir(_d) and _d not in os.environ.get("PATH", ""):
        os.environ["PATH"] = _d + os.pathsep + os.environ.get("PATH", "")

def _opt_import(name):
    try:
        return __import__(name)
    except Exception:
        return None

# ---------- psutil: conexiones y top talkers (base siempre) ----------
def connections_snapshot(limit=30):
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception as e:
        return {"error": str(e), "total": 0, "top_remote": []}
    remote_counter = collections.Counter()
    by_status = collections.Counter()
    suspicious = []
    for c in conns:
        try:
            by_status[c.status] += 1
            if c.raddr:
                ip = c.raddr.ip
                remote_counter[ip] += 1
                # puertos raros fuera de lo común
                if c.raddr.port not in (80, 443, 8443, 53, 22, 3389, 445, 3306, 5432, 1433, 25, 587, 993, 110):
                    if c.status == "ESTABLISHED" and c.raddr.port > 10000:
                        suspicious.append(f"{ip}:{c.raddr.port} ({c.status})")
        except Exception:
            continue
    top = []
    for ip, n in remote_counter.most_common(limit):
        try:
            host = socket.gethostbyaddr(ip)[0]
        except Exception:
            host = "-"
        top.append({"ip": ip, "host": host, "conexiones": n})
    return {"total": len(conns), "por_estado": dict(by_status),
            "top_remote": top[:15], "sospechosas": suspicious[:15]}

def _es_publica(ip: str) -> bool:
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
        return addr.is_global and not addr.is_multicast and not addr.is_reserved
    except Exception:
        return False

# ---------- Navegación insegura: HTTP plano hacia internet ----------
PLAIN_PORTS = (80, 8080, 8000, 3128, 8888)
def insecure_browsing():
    """Conexiones ESTABLISHED a IPs públicas por puertos sin TLS (http plano).
    HTTPS (443) no se reporta: es navegación segura."""
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception as e:
        return {"error": str(e), "hallazgos": []}
    por_ip = {}
    for c in conns:
        try:
            if not c.raddr or c.status != "ESTABLISHED":
                continue
            if c.raddr.port in PLAIN_PORTS and _es_publica(c.raddr.ip):
                e = por_ip.setdefault(c.raddr.ip, {"ip": c.raddr.ip, "puertos": set(), "n": 0, "pids": set()})
                e["puertos"].add(c.raddr.port)
                e["n"] += 1
                if c.pid:
                    e["pids"].add(c.pid)
        except Exception:
            continue
    hallazgos = []
    for ip, e in sorted(por_ip.items(), key=lambda kv: -kv[1]["n"])[:20]:
        try:
            host = socket.gethostbyaddr(ip)[0]
        except Exception:
            host = "-"
        proc = ""
        try:
            import psutil as _ps
            names = set()
            for pid in list(e["pids"])[:5]:
                try:
                    names.add(_ps.Process(pid).name())
                except Exception:
                    pass
            proc = ", ".join(sorted(names)) or "-"
        except Exception:
            pass
        hallazgos.append({"ip": ip, "host": host, "puertos": sorted(e["puertos"]),
                          "conexiones": e["n"], "procesos": proc})
    nivel = "OK" if not hallazgos else ("WARN" if len(hallazgos) < 5 else "CRITICO")
    return {"nivel": nivel, "total_ips": len(hallazgos),
            "resumen": "Sin navegación HTTP plana a internet ✅" if not hallazgos
                       else f"⚠️ {len(hallazgos)} destino(s) por HTTP sin cifrar",
            "hallazgos": hallazgos}

def _is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def _npcap_present():
    import os
    return os.path.exists(r"C:\Windows\System32\Npcap\wpcap.dll") or os.path.exists(r"C:\Windows\System32\wpcap.dll")

# ---------- Scapy: sniffing ----------
def scapy_sniff(seconds=8, packet_limit=500):
    try:
        import importlib
        scapy_all = importlib.import_module("scapy.all")
    except Exception:
        return {"disponible": False, "msg": "Scapy no instalado. pip install scapy + Npcap en Windows."}
    if not _npcap_present():
        return {"disponible": False, "msg": "Npcap no instalado. Instala Wireshark o Nmap (incluyen Npcap)."}
    if not _is_admin():
        return {"disponible": False, "msg": "Npcap OK pero el servidor no corre como administrador. Reinicia la app como admin para sniff L2 (clic derecho > Ejecutar como administrador). Mientras tanto usa Conexiones (psutil)."}
    try:
        pkts = scapy_all.sniff(timeout=seconds, count=packet_limit)
    except Exception as e:
        return {"disponible": False, "msg": f"Sniff falló aun como admin: {e}"}
    per_ip = collections.Counter()
    per_proto = collections.Counter()
    syn_ports = collections.defaultdict(set)  # src -> puertos (port-scan)
    for p in pkts:
        try:
            if p.haslayer("IP"):
                src = p["IP"].src
                per_ip[src] += len(p)
                per_proto[p["IP"].proto] += 1
                if p.haslayer("TCP") and p["TCP"].flags == "S":
                    syn_ports[src].add(int(p["TCP"].dport))
        except Exception:
            continue
    alertas = []
    for src, ports in syn_ports.items():
        if len(ports) >= 15:
            alertas.append(f"⚠️ Posible escaneo de puertos desde {src}: {len(ports)} puertos SYN")
    top = [{"ip": ip, "bytes": b} for ip, b in per_ip.most_common(15)]
    # navegación: top talkers = posible streaming/descarga
    if top and top[0]["bytes"] > 5_000_000:
        alertas.append(f"📡 Tráfico alto desde {top[0]['ip']}: {top[0]['bytes']/1e6:.1f}MB en {seconds}s (streaming/descarga?)")
    return {"disponible": True, "paquetes": len(pkts), "segundos": seconds,
            "top_talkers": top, "protocolos": dict(per_proto), "alertas": alertas}

# ---------- pyshark ----------
def pyshark_check():
    pyshark = _opt_import("pyshark")
    if not pyshark:
        return {"disponible": False, "msg": "pyshark no instalado (pip install pyshark + tshark/Wireshark)."}
    try:
        import shutil
        tshark = shutil.which("tshark")
        if not tshark:
            return {"disponible": False, "msg": "tshark no encontrado. Instala Wireshark."}
        return {"disponible": True, "msg": f"tshark OK en {tshark}. Listo para capturas profundas."}
    except Exception as e:
        return {"disponible": False, "msg": str(e)}

# ---------- Netmiko ----------
def netmiko_facts(cfg_net=None):
    netmiko = _opt_import("netmiko")
    if not netmiko:
        return {"disponible": False, "msg": "Netmiko no instalado (pip install netmiko)."}
    dev = (cfg_net or {}).get("netmiko") if cfg_net else None
    if not dev or not dev.get("host"):
        return {"disponible": True, "configurado": False,
                "msg": "Agrega en targets.yaml network.netmiko: {host, username, password, device_type} para SSH al router."}
    try:
        from netmiko import ConnectHandler
        conn = ConnectHandler(**{k: dev[k] for k in ("host", "username", "password", "device_type") if k in dev})
        out = conn.send_command("show version" if "ios" in dev.get("device_type", "") else "show system information")
        conn.disconnect()
        return {"disponible": True, "configurado": True, "resumen": out[:1500]}
    except Exception as e:
        return {"disponible": True, "configurado": True, "error": f"SSH falló: {e}"}

# ---------- NAPALM ----------
def napalm_facts(cfg_net=None):
    napalm = _opt_import("napalm")
    if not napalm:
        return {"disponible": False, "msg": "NAPALM no instalado (pip install napalm)."}
    dev = (cfg_net or {}).get("napalm") if cfg_net else None
    if not dev or not dev.get("hostname"):
        return {"disponible": True, "configurado": False,
                "msg": "Agrega network.napalm: {hostname, username, password, driver} para facts multivendor."}
    try:
        driver = napalm.get_network_driver(dev.get("driver", "ios"))
        d = driver(dev["hostname"], dev["username"], dev["password"])
        d.open()
        facts = d.get_facts()
        d.close()
        return {"disponible": True, "configurado": True, "facts": facts}
    except Exception as e:
        return {"disponible": True, "configurado": True, "error": f"NAPALM falló: {e}"}

# ---------- Diagnóstico de fallos ----------
def diagnose_faults(live: dict, http_results: list, devices: list):
    fallos = []
    gw = (live or {}).get("ping_gateway_ms")
    net = (live or {}).get("ping_internet_ms")
    app = (live or {}).get("ping_app_ms")
    if gw is None:
        fallos.append({"nivel": "CRITICO", "msg": "❌ Gateway no responde: falla LAN local, cable, switch o AP."})
    elif gw > 100:
        fallos.append({"nivel": "WARN", "msg": f"⚠️ Latencia alta al gateway: {gw}ms (congestión local o WiFi débil)."})
    if gw is not None and net is None:
        fallos.append({"nivel": "CRITICO", "msg": "❌ Hay LAN pero no internet: falla ISP o DNS/firewall. Revisar router."})
    elif net is not None and net is not None and net > 200:
        fallos.append({"nivel": "WARN", "msg": f"⚠️ Internet lento: {net}ms (ISP saturado o VPN)."})
    if net is not None and app is None:
        fallos.append({"nivel": "WARN", "msg": "⚠️ Hay internet pero app interna no responde por ping: posible caída servidor app o VLAN 200."})
    for h in (http_results or []):
        if not h.get("ok"):
            if "ERP XEO" in (h.get("name") or ""):
                fallos.append({"nivel": "CRITICO", "msg": f"🛑 ERP XEO CENTRAL caído: {h.get('name')} -> {h.get('detail','')[:160]}"})
            else:
                fallos.append({"nivel": "CRITICO", "msg": f"❌ Página caída: {h.get('name')} -> {h.get('detail','')[:160]}"})
    try:
        ins = insecure_browsing()
        if ins.get("hallazgos"):
            top = ", ".join(f"{x['ip']}:{','.join(map(str, x['puertos']))}" for x in ins["hallazgos"][:3])
            fallos.append({"nivel": "WARN" if ins.get("nivel") == "WARN" else "CRITICO",
                           "msg": f"🔓 Navegación insegura (HTTP sin cifrar): {ins['total_ips']} destino(s) ej. {top}"})
    except Exception:
        pass
    off = [d for d in (devices or []) if not d.get("online")]
    if len(off) >= 5:
        fallos.append({"nivel": "CRITICO", "msg": f"❌ {len(off)} equipos offline: posible switch apagado o corte eléctrico parcial."})
    if not fallos:
        fallos.append({"nivel": "OK", "msg": "✅ Sin fallos detectados: gateway, internet y páginas responden."})
    return fallos

def libraries_status():
    out = {}
    out["scapy"] = bool(_opt_import("scapy.all"))
    out["pyshark"] = bool(_opt_import("pyshark"))
    out["netmiko"] = bool(_opt_import("netmiko"))
    out["napalm"] = bool(_opt_import("napalm"))
    out["psutil"] = True
    return out
