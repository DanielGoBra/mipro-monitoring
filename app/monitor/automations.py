"""Automatizaciones con RUTAS UNIVERSALES (OneDrive/SharePoint) + tipo carpeta.
Soporta: file | folder | http | process
- ${USERPROFILE}, %VAR%, ~, * wildcards
- Si la ruta no existe, busca por nombre de carpeta en raíces conocidas.
"""
import os
import time
import glob
import fnmatch
import psutil
from .http_check import check_http

KNOWN_ROOTS = []
def _build_roots():
    global KNOWN_ROOTS
    up = os.environ.get("USERPROFILE", os.path.expanduser("~"))
    od = os.environ.get("OneDrive", "")
    odc = os.environ.get("OneDriveCommercial", "")
    cands = [
        os.path.join(up, "Inklusiva s.a.s"),
        os.path.join(up, "OneDrive - Inklusiva s.a.s"),
        od, odc,
        os.path.join(od, "Documentos en RED") if od else "",
        up,
    ]
    KNOWN_ROOTS = [c for c in cands if c and os.path.isdir(c)]
_build_roots()

def expand_universal(path: str) -> str:
    if not path:
        return path
    # ${VAR} y %VAR% y ~
    path = os.path.expandvars(path.replace("${USERPROFILE}", "%USERPROFILE%").replace("$USERPROFILE", "%USERPROFILE%"))
    path = os.path.expanduser(path)
    return path

def resolve_smart(path: str) -> str:
    """Si tiene *, hace glob. Si no existe, busca la carpeta base en KNOWN_ROOTS."""
    exp = expand_universal(path)
    if "*" in exp or "?" in exp:
        hits = glob.glob(exp)
        if hits:
            # preferir el más reciente
            hits.sort(key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0, reverse=True)
            return hits[0]
    if os.path.exists(exp):
        return exp
    # buscar por nombre de carpeta final en raíces conocidas (máx 3 niveles)
    base = os.path.basename(exp.rstrip("\\/"))
    if base and len(base) > 2:
        for root in KNOWN_ROOTS:
            for dirpath, dirnames, _ in os.walk(root):
                depth = dirpath[len(root):].count(os.sep)
                if depth > 4:
                    dirnames[:] = []
                    continue
                if base.lower() in [d.lower() for d in dirnames]:
                    idx = [d.lower() for d in dirnames].index(base.lower())
                    return os.path.join(dirpath, dirnames[idx])
                # coincidencia parcial mora-tools / ANEXO 4
                for d in dirnames:
                    if base.lower() == d.lower():
                        return os.path.join(dirpath, d)
    return exp  # aunque no exista, para mensaje claro

def format_edad(age_min: float) -> str:
    """Humano para técnicos: min -> 'hace 25 min' / 'hace 5h' / 'hace 3 días con 18 horas'."""
    if age_min < 1:
        return "hace menos de 1 min"
    if age_min < 60:
        return f"hace {int(age_min)} min"
    hours = age_min / 60
    if hours < 48:
        h = int(hours)
        m = int((hours - h) * 60)
        return f"hace {h}h con {m:02d} min" if m else f"hace {h} horas"
    days = int(hours // 24)
    rest_h = int(hours % 24)
    if rest_h:
        return f"hace {days} días con {rest_h} horas"
    return f"hace {days} días"

SKIP_DIRS = ("__pycache__", ".git", "node_modules")
SKIP_PREFIX = ("~$", ".~")

def _match_any(fname: str, pats: list) -> bool:
    fl = fname.lower()
    if fname.startswith(SKIP_PREFIX) or fl.endswith((".tmp", ".temp", ".swp")):
        return False
    return any(fnmatch.fnmatch(fl, p.lower()) for p in pats)

def check_folder(name, path, patterns="*.xlsm,*.xlsx,*.csv,*.log,*.txt,*.py,*.bat,*.ps1", max_age_minutes=4320):
    real = resolve_smart(path)
    if not os.path.exists(real):
        return {"name": name, "ok": False, "latency_ms": 0, "status_code": None,
                "detail": f"Ruta no encontrada (universal): {path} -> {real}"}
    pats = [p.strip() for p in patterns.split(",") if p.strip()]
    files = []
    if os.path.isfile(real):
        files = [real]
    else:
        # RECURSIVO total: las corridas de hoy escriben en subcarpetas (logs/, OCTUBRE 5/, FEBRERO/)
        for dirpath, dirnames, filenames in os.walk(real):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                if _match_any(fn, pats):
                    files.append(os.path.join(dirpath, fn))
    if not files:
        return {"name": name, "ok": False, "latency_ms": 0, "status_code": None,
                "detail": f"Sin evidencias ({patterns}) en {real}"}
    files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    newest = files[0]
    age_min = (time.time() - os.path.getmtime(newest)) / 60
    total_mb = sum(os.path.getsize(f) for f in files) / 1024 / 1024
    ok = age_min <= max_age_minutes
    rel = os.path.basename(newest)
    edad = format_edad(age_min)
    max_h = f"hace {int(max_age_minutes/60/24)} días" if max_age_minutes >= 2880 else f"{max_age_minutes/60:.0f}h"
    top3 = ", ".join(os.path.basename(f) for f in files[:3])
    try:
        rel_dir = os.path.relpath(os.path.dirname(newest), real)
    except Exception:
        rel_dir = ""
    detail = (f"📁 {rel_dir if rel_dir != '.' else 'raíz'} | {len(files)} evidencias ({total_mb:.1f}MB) | "
              f"último: {rel} | {edad} (máx {max_h}) | recientes: {top3}")
    return {"name": name, "ok": ok, "latency_ms": 0, "status_code": None, "detail": detail,
            "age_min": round(age_min, 1), "age_human": edad, "path": real, "files": len(files)}

def check_automation(item: dict):
    name = item.get("name", "sin-nombre")
    typ = item.get("type", "http")
    try:
        if typ == "file":
            path = resolve_smart(item.get("path", ""))
            max_age = int(item.get("max_age_minutes", 1440))
            if not os.path.exists(path):
                return {"name": name, "ok": False, "latency_ms": 0, "status_code": None, "detail": f"No existe: {path}"}
            age_min = (time.time() - os.path.getmtime(path)) / 60
            ok = age_min <= max_age
            return {"name": name, "ok": ok, "latency_ms": 0, "status_code": None,
                    "detail": f"{os.path.basename(path)} | {format_edad(age_min)} | {path}",
                    "age_min": round(age_min, 1), "age_human": format_edad(age_min)}
        elif typ == "folder":
            return check_folder(name, item.get("path", ""),
                                item.get("patterns", "*.xlsm,*.xlsx,*.csv,*.log,*.txt,*.py,*.bat,*.ps1"),
                                int(item.get("max_age_minutes", 4320)))
        elif typ == "process":
            pname = (item.get("process_name") or "").lower()
            found = any(pname in (p.info.get("name") or "").lower() for p in psutil.process_iter(["name"]))
            return {"name": name, "ok": found, "latency_ms": 0, "status_code": None,
                    "detail": f"Proceso {'en ejecución' if found else 'NO encontrado'}: {pname}"}
        elif typ == "http":
            from .http_check import check_http as _ch
            return _ch(name, item.get("url"), item.get("method", "GET"),
                       int(item.get("timeout", 10)), item.get("expect_status", 200),
                       item.get("verify_ssl", True))
        else:
            return {"name": name, "ok": False, "latency_ms": 0, "status_code": None, "detail": f"Tipo desconocido: {typ}"}
    except Exception as e:
        return {"name": name, "ok": False, "latency_ms": 0, "status_code": None, "detail": f"{type(e).__name__}: {e}"}
