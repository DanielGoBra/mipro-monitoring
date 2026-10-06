"""Operaciones T.I: SNMP del router, reporte PDF gerencial."""
import time
import os

# ---------- SNMP: Mbps real por interfaz + tabla ARP ----------
RFC1213 = {
    "descr": "1.3.6.1.2.1.2.2.1.2",
    "in_oct": "1.3.6.1.2.1.2.2.1.10",
    "out_oct": "1.3.6.1.2.1.2.2.1.16",
    "hc_in": "1.3.6.1.2.1.31.1.1.1.6",
    "hc_out": "1.3.6.1.2.1.31.1.1.1.10",
    "status": "1.3.6.1.2.1.2.2.1.8",
}

def _snmp_walk(host, community, oid, port=161, timeout=4):
    try:
        from pysnmp.hlapi import (SnmpEngine, CommunityData, UdpTransportTarget,
                                  ContextData, ObjectType, ObjectIdentity, nextCmd)
    except Exception:
        return {"error": "pip install pysnmp"}
    out = {}
    try:
        for err_ind, err_st, err_idx, binds in nextCmd(
                SnmpEngine(), CommunityData(community, mpModel=1),
                UdpTransportTarget((host, port), timeout=timeout, retries=1),
                ContextData(), ObjectType(ObjectIdentity(oid)), lexicographicMode=False):
            if err_ind or err_st:
                return {"error": str(err_ind or err_st)}
            for b in binds:
                oi, val = b[0], b[1]
                idx = str(oi).split(".")[-1]
                out[idx] = str(val)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    return out

def snmp_interfaces(host="192.168.1.1", community="public", wait_s=5):
    """Tasa real Mbps por interfaz del router (2 lecturas separadas wait_s)."""
    hc_in = _snmp_walk(host, community, RFC1213["hc_in"])
    if isinstance(hc_in, dict) and "error" in hc_in and not hc_in:
        pass
    if "error" in hc_in:
        # probar contadores 32-bit
        hc_in, hc_out, descr = (_snmp_walk(host, community, RFC1213["in_oct"]),
                               _snmp_walk(host, community, RFC1213["out_oct"]),
                               _snmp_walk(host, community, RFC1213["descr"]))
        is64 = False
    else:
        hc_out = _snmp_walk(host, community, RFC1213["hc_out"])
        descr = _snmp_walk(host, community, RFC1213["descr"])
        is64 = True
    if "error" in hc_in:
        return {"disponible": False, "msg": f"SNMP sin respuesta en {host} ({hc_in['error']}). Activa SNMP v2c read-only en el router y autoriza la IP de este servidor."}
    if "error" in hc_out:
        return {"disponible": False, "msg": f"SNMP incompleto: {hc_out['error']}"}
    t0 = time.time()
    time.sleep(wait_s)
    dt = time.time() - t0
    base = RFC1213["hc_in"] if is64 else RFC1213["in_oct"]
    base_o = RFC1213["hc_out"] if is64 else RFC1213["out_oct"]
    in2 = _snmp_walk(host, community, base)
    out2 = _snmp_walk(host, community, base_o)
    if "error" in in2:
        return {"disponible": False, "msg": in2["error"]}
    rows = []
    for idx, v0 in hc_in.items():
        try:
            down = (int(in2.get(idx, v0)) - int(v0)) * 8 / dt / 1e6
            up = (int(out2.get(idx, hc_out.get(idx, 0))) - int(hc_out.get(idx, 0))) * 8 / dt / 1e6
            rows.append({"if": idx, "nombre": descr.get(idx, "-"),
                         "down_mbps": round(max(0, down), 2), "up_mbps": round(max(0, up), 2)})
        except Exception:
            continue
    rows.sort(key=lambda r: -(r["down_mbps"] + r["up_mbps"]))
    return {"disponible": True, "host": host, "interfaces": rows[:16],
            "nota": "Mbps REAL por interfaz del router vía SNMP (no estimado)."}

# ---------- Reporte PDF gerencial ----------
def _txt(s):
    """Sanitiza a latin-1 para fuentes core del PDF (⭐→*, emojis fuera)."""
    if s is None:
        return "-"
    return str(s).replace("⭐", "*").encode("latin-1", "replace").decode("latin-1")

def build_pdf(path, days=7):
    try:
        from fpdf import FPDF
    except Exception:
        return {"error": "pip install fpdf2"}
    from app.database import sla_stats, incidents_list
    sla = sla_stats(days=days)
    inc = incidents_list(limit=50)
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, "MiPro Monitoring - Reporte T.I", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 8, f"Periodo: ultimos {days} dias - {time.strftime('%Y-%m-%d %H:%M')}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 9, "SLA por servicio", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(80, 7, "Servicio", border=1)
    pdf.cell(25, 7, "Uptime", border=1)
    pdf.cell(25, 7, "p95 ms", border=1)
    pdf.cell(25, 7, "Checks", border=1, new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    for s in sla:
        pdf.cell(80, 6, _txt(s["name"][:48]), border=1)
        pdf.cell(25, 6, f"{s['uptime']}%", border=1)
        pdf.cell(25, 6, str(s["p95_ms"] or "-"), border=1)
        pdf.cell(25, 6, str(s["checks"]), border=1, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 9, "Incidentes", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    if not inc:
        pdf.cell(0, 7, "Sin incidentes en el periodo.", new_x="LMARGIN", new_y="NEXT")
    for i in inc[:30]:
        ini = time.strftime("%Y-%m-%d %H:%M", time.localtime(i["ts_start"]))
        fin = time.strftime("%Y-%m-%d %H:%M", time.localtime(i["ts_end"])) if i["ts_end"] else "abierto"
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 6, _txt(f"[{i['status']}] {i['title']} ({i['level']}) {ini} -> {fin}"))
    pdf.output(path)
    return {"ok": True, "path": path}
