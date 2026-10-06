"""Auditoría de encabezados HTTP + TLS para páginas.
Verifica que los encabezados funcionen correctamente y puntúa seguridad.
"""
import time
import ssl
import socket
from urllib.parse import urlparse
import httpx

CHECKS = [
    ("strict-transport-security", "HSTS", 20, "Falta HSTS (https seguro)"),
    ("x-frame-options", "Clickjacking", 15, "Falta X-Frame-Options"),
    ("x-content-type-options", "MIME-sniff", 15, "Falta X-Content-Type-Options: nosniff"),
    ("referrer-policy", "Referrer", 10, "Falta Referrer-Policy"),
    ("content-security-policy", "CSP", 15, "Falta Content-Security-Policy"),
    ("permissions-policy", "Permissions", 5, "Falta Permissions-Policy"),
]

def cert_days_left(hostname: str, port=443) -> int | None:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as s:
                cert = s.getpeercert()
                import datetime
                exp = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                return (exp - datetime.datetime.utcnow()).days
    except Exception:
        return None

def audit_headers(url: str, timeout=15, verify_ssl=True):
    start = time.perf_counter()
    # 1er intento con verify según config; si falla por SSL autofirmado (:8443 interno), reintenta sin verificar
    verify = verify_ssl
    r = None
    last_err = None
    for attempt in (verify, False) if verify else (False,):
        try:
            r = httpx.get(url, timeout=timeout, follow_redirects=True, verify=attempt)
            if attempt is False and verify:
                last_err = "self-signed"
            break
        except Exception as e:
            msg = str(e)
            if "CERTIFICATE_VERIFY_FAILED" in msg or "self-signed" in msg or "SSL" in type(e).__name__:
                last_err = e
                continue
            ms = round((time.perf_counter() - start) * 1000, 1)
            return {"url": url, "ok": False, "status_code": None, "latency_ms": ms,
                    "score": 0, "server": "-", "cert_days": None,
                    "issues": [f"{type(e).__name__}: {e}"], "passed": [],
                    "detail": f"{type(e).__name__}: {e}"}
    if r is None:
        ms = round((time.perf_counter() - start) * 1000, 1)
        # self-signed en app interna: no es fallo crítico, se audita igual sin verify
        try:
            r = httpx.get(url, timeout=timeout, follow_redirects=True, verify=False)
            last_err = "self-signed (audit sin verify)"
        except Exception as e:
            return {"url": url, "ok": False, "status_code": None, "latency_ms": ms,
                    "score": 0, "server": "-", "cert_days": None,
                    "issues": [f"{type(e).__name__}: {e}"], "passed": [],
                    "detail": f"{type(e).__name__}: {e}"}
    try:
        ms = round((time.perf_counter() - start) * 1000, 1)
        hdrs = {k.lower(): v for k, v in r.headers.items()}
        score = 40  # base por responder 200
        if r.status_code < 400:
            score += 10
        issues, passed = [], []
        for h, label, pts, msg in CHECKS:
            if h in hdrs:
                score += pts
                passed.append(f"{label}: {hdrs[h][:80]}")
            else:
                issues.append(msg)
        # Server disclosure (informativo, no resta mucho)
        server = r.headers.get("server", r.headers.get("Server", "-"))
        # cert
        host = urlparse(url).hostname or ""
        is_https = url.lower().startswith("https")
        cert_days = cert_days_left(host) if is_https else None
        if is_https and cert_days is not None:
            if cert_days > 30:
                score += 5
                passed.append(f"Cert OK: {cert_days} días")
            elif cert_days > 0:
                issues.append(f"Cert por vencer: {cert_days} días")
            else:
                issues.append("Cert vencido o inválido")
                score -= 20
        score = max(0, min(100, score))
        if last_err == "self-signed (audit sin verify)" or last_err:
            issues.append("Cert autofirmado interno (:8443) - auditable solo sin verify")
        ok = r.status_code < 400 and score >= 50
        return {
            "url": url, "ok": ok, "status_code": r.status_code, "latency_ms": ms,
            "score": score, "server": server, "cert_days": cert_days,
            "issues": issues, "passed": passed,
            "detail": f"{r.status_code} en {ms}ms · score {score}/100 · server {server}",
        }
    except Exception as e:
        ms = round((time.perf_counter() - start) * 1000, 1)
        return {"url": url, "ok": False, "status_code": None, "latency_ms": ms,
                "score": 0, "server": "-", "cert_days": None,
                "issues": [f"{type(e).__name__}: {e}"], "passed": [],
                "detail": f"{type(e).__name__}: {e}"}
