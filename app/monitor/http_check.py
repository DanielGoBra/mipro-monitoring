"""Chequeo HTTP + TCP para APIs, páginas y servicios que no son web (ERP XEO).
Soporta SSL autofirmado :8443 y tcp://host:puerto para servicios puros."""
import time
import socket
import httpx

def check_tcp(name, host, port, timeout=5, retries=1):
    """Chequeo TCP limpio: solo conecta y escucha banner pasivo.
    NUNCA envía HEAD/GET: no genera 400s en los logs del servidor monitoreado.
    No usa ping: XEO lo bloquea. Reintenta 1 vez ante timeouts."""
    attempt = 0
    while True:
        start = time.perf_counter()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, int(port)))
            latency = round((time.perf_counter() - start) * 1000, 1)
            try:
                s.settimeout(0.8)
                raw = s.recv(120)
                banner = raw.decode("utf-8", "ignore").replace("\n", " ").strip()[:80] or "puerto abierto"
            except Exception:
                banner = "puerto abierto"
            return {"name": name, "ok": True, "latency_ms": latency, "status_code": None,
                    "detail": f"TCP {host}:{port} OK en {latency}ms · {banner}"}
        except Exception as e:
            latency = round((time.perf_counter() - start) * 1000, 1)
            if attempt < retries and "timed out" in str(e):
                attempt += 1
                try:
                    s.close()
                except Exception:
                    pass
                time.sleep(1)
                continue
            return {"name": name, "ok": False, "latency_ms": latency, "status_code": None,
                    "detail": f"TCP {host}:{port} FALLO: {type(e).__name__}"}
        finally:
            try:
                s.close()
            except Exception:
                pass

def check_target(t: dict):
    """Despacha http(s):// o tcp://host:puerto según el target."""
    url = t.get("url", "")
    if url.startswith("tcp://"):
        hp = url[6:].split(":")
        return check_tcp(t.get("name", url), hp[0], int(hp[1]) if len(hp) > 1 else 80,
                         int(t.get("timeout", 5)))
    return check_http(t.get("name"), url, t.get("method", "GET"),
                      int(t.get("timeout", 10)), t.get("expect_status", 200),
                      t.get("verify_ssl", True))

def check_http(name, url, method="GET", timeout=10, expect_status=200, verify_ssl=True):
    start = time.perf_counter()
    try:
        # verify=False para inklusivapp:8443 y servicios internos con cert propio
        verify = verify_ssl if isinstance(verify_ssl, bool) else True
        if isinstance(verify_ssl, str):
            verify = verify_ssl.lower() not in ("false", "0", "no")
        r = httpx.request(method, url, timeout=timeout, follow_redirects=True, verify=verify)
        latency = round((time.perf_counter() - start) * 1000, 1)
        if isinstance(expect_status, list):
            ok = r.status_code in expect_status
        elif expect_status:
            ok = (r.status_code == expect_status)
        else:
            ok = (r.status_code < 400)
        return {
            "name": name, "ok": ok, "latency_ms": latency,
            "status_code": r.status_code,
            "detail": f"{method} {url} -> {r.status_code} en {latency}ms",
        }
    except Exception as e:
        latency = round((time.perf_counter() - start) * 1000, 1)
        return {
            "name": name, "ok": False, "latency_ms": latency,
            "status_code": None, "detail": f"{type(e).__name__}: {e}",
        }
