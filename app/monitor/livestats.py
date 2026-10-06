"""Métricas en vivo: ancho de banda Mbps + pings a gateway/internet/app."""
import time
import psutil
import subprocess
import re
import platform

_prev_net = None
_prev_ts = None

def get_bandwidth_mbps():
    """Tasa real de bajada/subida en Mbps (diferencia de contadores)."""
    global _prev_net, _prev_ts
    now = time.time()
    cur = psutil.net_io_counters()
    if _prev_net is None:
        _prev_net, _prev_ts = cur, now
        return 0.0, 0.0
    dt = max(0.1, now - _prev_ts)
    down = (cur.bytes_recv - _prev_net.bytes_recv) * 8 / dt / 1_000_000
    up = (cur.bytes_sent - _prev_net.bytes_sent) * 8 / dt / 1_000_000
    _prev_net, _prev_ts = cur, now
    return round(max(0, down), 2), round(max(0, up), 2)

def dns_probe(names, timeout=3):
    """Tiempo de resolución DNS de los nombres que ya monitorea la consola."""
    import socket
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    rows = []
    seen = set()
    try:
        for raw in names or []:
            name = str(raw or "").strip().lower().rstrip(".")
            if not name or name in seen or _is_ip(name):
                continue
            seen.add(name)
            t0 = time.perf_counter()
            try:
                infos = socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM)
                ip = infos[0][4][0]
                rows.append({"name": name, "ok": True, "ip": ip, "ms": round((time.perf_counter() - t0) * 1000, 1)})
            except Exception as e:
                rows.append({"name": name, "ok": False, "ip": "", "ms": None, "error": type(e).__name__})
            if len(rows) >= 8:
                break
    finally:
        socket.setdefaulttimeout(old)
    return rows

def _is_ip(name: str) -> bool:
    parts = name.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

def ping_ms(host: str, timeout_ms=900):
    system = platform.system().lower()
    try:
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", host]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
        out = (res.stdout or "") + (res.stderr or "")
        m = re.search(r"tiempo[=<]\s*(\d+)\s*ms", out, re.IGNORECASE)
        if not m:
            m = re.search(r"time[=<]\s*(\d+\.?\d*)\s*ms", out, re.IGNORECASE)
        if m:
            return float(m.group(1))
        return None if res.returncode != 0 else 1.0
    except Exception:
        return None

def get_live_snapshot(gateway="192.168.1.1", internet="8.8.8.8", app_host="inklusivapp.inklusiva.co"):
    down, up = get_bandwidth_mbps()
    return {
        "ts": int(time.time()),
        "down_mbps": down,
        "up_mbps": up,
        "ping_gateway_ms": ping_ms(gateway),
        "ping_internet_ms": ping_ms(internet),
        "ping_app_ms": ping_ms(app_host),
    }
