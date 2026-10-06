"""Top-10 ciberseguridad (artículo Medium 2025) integrado a la app maestra.
1 Scapy ✅ (security.py) · 2 Nmap · 3 Requests · 4 BeautifulSoup · 5 Pyshark ✅
6 Paramiko · 7 Cryptography · 8 Socket (stdlib) · 9 Volatility · 10 Shodan
Todo con degradación elegante: si falta la lib o el binario, se explica cómo activarlo.
"""
import socket
import ssl
import re
import time
import os
import shutil

# Rutas típicas Windows para que nmap/tshark se encuentren aunque no estén en PATH
for _d in (r"C:\Program Files (x86)\Nmap", r"C:\Program Files\Nmap",
           r"C:\Program Files\Wireshark", r"C:\Program Files (x86)\Wireshark"):
    if os.path.isdir(_d) and _d not in os.environ.get("PATH", ""):
        os.environ["PATH"] = _d + os.pathsep + os.environ.get("PATH", "")

def _imp(name):
    try:
        import importlib
        return importlib.import_module(name)
    except Exception:
        return None

# ---------- 2. Nmap (python-nmap, requiere binario nmap) ----------
def nmap_scan(target="127.0.0.1", ports="80,443,22,3389,8080,8443"):
    nm_mod = _imp("nmap")
    if nm_mod:
        try:
            nm = nm_mod.PortScanner()
            # -sT = connect scan (funciona sin admin); sin -F porque es incompatible con -p explícitos
            nm.scan(target, ports, arguments="-T4 -sT --open")
            hosts = []
            for h in nm.all_hosts():
                entry = {"host": h, "state": nm[h].state(), "tcp": {}}
                for proto in nm[h].all_protocols():
                    for p, info in nm[h][proto].items():
                        entry["tcp"][p] = info.get("state")
                hosts.append(entry)
            return {"motor": "nmap", "hosts": hosts}
        except Exception as e:
            msg = str(e)
            if "nmap program was not found" in msg or "not found in path" in msg.lower():
                pass  # caer a socket (nmap.exe no visible para este proceso)
            else:
                return {"motor": "nmap", "error": msg}
    # fallback socket (8. Socket stdlib) con banner grabbing
    out = []
    try:
        for p in [int(x) for x in str(ports).split(",") if str(x).strip().isdigit()]:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.6)
            try:
                s.connect((target, p))
                try:
                    s.settimeout(1.0)
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(200).decode("utf-8", "ignore")[:160]
                except Exception:
                    banner = "abierto (sin banner)"
                out.append({"puerto": p, "state": "open", "banner": banner})
            except Exception:
                pass
            finally:
                s.close()
    except Exception as e:
        return {"motor": "socket-fallback", "error": str(e)}
    import shutil
    if not shutil.which("nmap"):
        return {"motor": "socket-fallback (nmap.exe no en PATH: reinicia el servidor o agrega C:\\Program Files (x86)\\Nmap al PATH)",
                "host": target, "open": out}
    return {"motor": "socket-fallback (nmap instalado pero sin permiso/tiempo; reintenta)",
            "host": target, "open": out}

# ---------- 3+4. Requests + BeautifulSoup: page intel / OSINT ligero ----------
def page_intel(url: str, timeout=12):
    req = _imp("requests")
    bs = _imp("bs4")
    if not req:
        return {"error": "pip install requests"}
    try:
        r = req.get(url, timeout=timeout, verify=False)
        html = r.text or ""
        info = {"status": r.status_code, "bytes": len(html), "server": r.headers.get("Server", "-")}
        if not bs:
            return {**info, "nota": "pip install beautifulsoup4 para title/forms/tech"}
        soup = bs.BeautifulSoup(html, "html.parser")
        title = soup.title.string.strip() if soup.title and soup.title.string else "-"
        forms = len(soup.find_all("form"))
        logins = len([f for f in soup.find_all("input", {"type": "password"})])
        scripts = len(soup.find_all("script"))
        low = html.lower()
        tech = []
        if "wp-content" in low or "wordpress" in low:
            tech.append("WordPress")
        if "react" in low:
            tech.append("React")
        if "angular" in low:
            tech.append("Angular")
        if "django" in low or "csrfmiddlewaretoken" in low:
            tech.append("Django")
        if "laravel" in low:
            tech.append("Laravel")
        emails = sorted(set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", html)))[:10]
        return {**info, "title": title[:120], "forms": forms, "login_forms": logins,
                "scripts": scripts, "tech": tech, "emails_publicos": emails}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}

# ---------- 6. Paramiko: auditoría SSH sin fuerza bruta ----------
def ssh_audit(host: str, port=22):
    # banner primero (socket)
    banner = "-"
    try:
        s = socket.create_connection((host, port), timeout=5)
        s.settimeout(3)
        banner = s.recv(200).decode("utf-8", "ignore").strip()[:120]
        s.close()
    except Exception as e:
        return {"host": host, "port": port, "abierto": False, "detalle": f"Cerrado o filtrado: {e}"}
    pm = _imp("paramiko")
    if not pm:
        return {"host": host, "port": port, "abierto": True, "banner": banner,
                "nota": "pip install paramiko para listar métodos de auth"}
    try:
        t = pm.Transport((host, port))
        t.start_client(timeout=8)
        # solo anuncia métodos si el servidor los expone sin auth (no probamos claves)
        try:
            t.auth_none("nadie")
        except Exception:
            pass
        t.close()
        return {"host": host, "port": port, "abierto": True, "banner": banner,
                "nota": "SSH expuesto: restringe por firewall/VPN y desactiva password si usas llaves"}
    except Exception as e:
        return {"host": host, "port": port, "abierto": True, "banner": banner, "detalle": str(e)[:200]}

# ---------- 7. Cryptography: análisis profundo del cert ----------
def cert_deep(hostname: str, port=443):
    cg = _imp("cryptography")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as s:
                der = s.getpeercert(binary_form=True)
                cipher = s.cipher()
    except Exception as e:
        return {"error": f"No se pudo negociar TLS: {e}"}
    if not cg:
        return {"cipher": cipher, "nota": "pip install cryptography para subject/issuer/SAN/firma"}
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        cert = x509.load_der_x509_certificate(der, default_backend())
        import datetime
        days = (cert.not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc)).days \
            if hasattr(cert, "not_valid_after_utc") else (cert.not_valid_after - datetime.datetime.utcnow()).days
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except Exception:
            san = []
        sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "?"
        debil = []
        if sig.lower().replace("-", "") in ("sha1", "md5"):
            debil.append(f"Firma débil: {sig}")
        if days < 0:
            debil.append("Vencido")
        elif days < 30:
            debil.append(f"Por vencer: {days} días")
        return {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
                "san": san[:10], "expira_dias": days, "firma": sig, "cipher": cipher,
                "alertas": debil or ["OK"]}
    except Exception as e:
        return {"error": str(e)}

# ---------- 10. Shodan (requiere API key) ----------
def shodan_lookup(ip: str, api_key=""):
    import os
    key = api_key or os.environ.get("SHODAN_API_KEY", "")
    if not key:
        # archivo local untracked (shodan.key, ignorado por git) como alternativa a env
        try:
            _kf = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "shodan.key")
            if os.path.exists(_kf):
                with open(_kf, encoding="utf-8") as _f:
                    key = _f.read().strip()
        except Exception:
            pass
    if not key:
        return {"configurado": False, "msg": "Falta API key: crea shodan.key (local, no se sube) o define SHODAN_API_KEY."}
    sh = _imp("shodan")
    if not sh:
        return {"configurado": False, "msg": "pip install shodan"}
    try:
        api = sh.Shodan(key)
        return {"configurado": True, "data": api.host(ip)}
    except Exception as e:
        return {"configurado": True, "error": str(e)[:300]}

# ---------- 9. Volatility + auditoría de procesos liviana ----------
def volatility_status():
    v = _imp("volatility3")
    if v:
        return {"disponible": True, "msg": "Volatility3 disponible. Apunta a un dump de memoria para forense."}
    return {"disponible": False, "msg": "Volatility es forense offline (dumps de RAM). Alternativa en vivo abajo: auditoría de procesos con psutil."}

SOSPECHOSOS = ("mimikatz", "psexec", "cobalt", "meterpreter", "powershell -enc", "wmic ", "nishang",
               "sekurlsa", "procdump", "gsecdump", "pypykatz", "ransom", "cryptominer", "xmrig")

def process_audit():
    import psutil
    hall = []
    try:
        for p in psutil.process_iter(["pid", "name", "exe", "cmdline", "cpu_percent"]):
            try:
                cmd = " ".join(p.info.get("cmdline") or []).lower()
                name = (p.info.get("name") or "").lower()
                exe = (p.info.get("exe") or "").lower()
                motive = ""
                if any(s in cmd or s in name for s in SOSPECHOSOS):
                    motive = "nombre/línea coincide con herramienta de ataque"
                elif "temp" in exe and name.endswith(".exe") and (p.info.get("cpu_percent") or 0) > 20:
                    motive = "ejecutable en TEMP con CPU alto"
                if motive:
                    hall.append({"pid": p.info["pid"], "name": p.info.get("name"), "motivo": motive, "cmd": cmd[:200]})
            except Exception:
                continue
    except Exception as e:
        return {"error": str(e)}
    return {"revisados": "ok", "sospechosos": hall[:20],
            "veredicto": "✅ Limpio (heurística básica)" if not hall else f"⚠️ {len(hall)} proceso(s) a revisar"}

def libraries10():
    return {
        "scapy": bool(_imp("scapy.all")),
        "nmap": bool(_imp("nmap")),
        "requests": bool(_imp("requests")),
        "bs4": bool(_imp("bs4")),
        "pyshark": bool(_imp("pyshark")),
        "paramiko": bool(_imp("paramiko")),
        "cryptography": bool(_imp("cryptography")),
        "socket": True,
        "volatility": bool(_imp("volatility3")),
        "shodan": bool(_imp("shodan")),
        "netmiko": bool(_imp("netmiko")),
        "napalm": bool(_imp("napalm")),
    }
