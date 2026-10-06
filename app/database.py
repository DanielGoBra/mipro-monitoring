"""SQLite liviano. Historial para gráficas simultáneas en tiempo real."""
import sqlite3
import os
import time

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), "monitoring.db"))

def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    conn.execute("""
    CREATE TABLE IF NOT EXISTS checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        category TEXT NOT NULL,
        name TEXT NOT NULL,
        ok INTEGER NOT NULL,
        latency_ms REAL,
        status_code INTEGER,
        detail TEXT
    )""")
    conn.execute("""
    CREATE TABLE IF NOT EXISTS system_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        cpu REAL, ram REAL, disk REAL,
        net_sent_mb REAL, net_recv_mb REAL
    )""")
    conn.execute("""
    CREATE TABLE IF NOT EXISTS live_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        down_mbps REAL, up_mbps REAL,
        ping_gateway_ms REAL, ping_internet_ms REAL, ping_app_ms REAL,
        cpu REAL, ram REAL
    )""")
    conn.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL,
        title TEXT NOT NULL,
        level TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        ts_start INTEGER NOT NULL,
        ts_end INTEGER,
        detail TEXT,
        ack_by TEXT
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_checks_ts ON checks(ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_live_ts ON live_metrics(ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_inc_key ON incidents(key, status)")
    conn.commit()
    conn.close()

def incident_open(key, title, level, detail=""):
    conn = get_conn()
    row = conn.execute("SELECT id FROM incidents WHERE key=? AND status IN ('open','ack')", (key,)).fetchone()
    if row:
        conn.close()
        return row["id"]
    cur = conn.execute(
        "INSERT INTO incidents (key, title, level, status, ts_start, detail) VALUES (?,?,?,?,?,?)",
        (key, title, level, "open", int(time.time()), detail[:1000]))
    iid = cur.lastrowid
    conn.commit()
    conn.close()
    return iid

def incident_resolve(key):
    conn = get_conn()
    conn.execute("UPDATE incidents SET status='resolved', ts_end=? WHERE key=? AND status IN ('open','ack')",
                 (int(time.time()), key))
    n = conn.total_changes
    conn.commit()
    conn.close()
    return n

def incident_ack(iid, by="soporte"):
    conn = get_conn()
    conn.execute("UPDATE incidents SET status='ack', ack_by=? WHERE id=? AND status='open'", (by, iid))
    conn.commit()
    conn.close()

def incidents_list(status="", limit=100):
    conn = get_conn()
    if status:
        rows = conn.execute("SELECT * FROM incidents WHERE status=? ORDER BY ts_start DESC LIMIT ?", (status, limit)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM incidents ORDER BY ts_start DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def sla_stats(days=30, limit=30000):
    """Uptime %, p95 y promedio de latencia por servicio."""
    import statistics
    conn = get_conn()
    since = int(time.time()) - days * 86400
    rows = conn.execute("SELECT category, name, ok, latency_ms FROM checks WHERE ts>=? LIMIT ?",
                        (since, limit)).fetchall()
    conn.close()
    agg = {}
    for r in rows:
        a = agg.setdefault((r["category"], r["name"]), {"n": 0, "ok": 0, "lat": []})
        a["n"] += 1
        a["ok"] += r["ok"]
        if r["latency_ms"] is not None:
            a["lat"].append(r["latency_ms"])
    out = []
    for (cat, name), a in sorted(agg.items()):
        lat = sorted(a["lat"])
        p95 = lat[min(len(lat) - 1, int(len(lat) * 0.95))] if lat else None
        out.append({"category": cat, "name": name, "checks": a["n"],
                    "uptime": round(a["ok"] / a["n"] * 100, 2) if a["n"] else 0,
                    "p95_ms": round(p95, 1) if p95 is not None else None,
                    "avg_ms": round(sum(lat) / len(lat), 1) if lat else None})
    return out

def save_check(category, name, ok, latency_ms=None, status_code=None, detail=""):
    conn = get_conn()
    conn.execute(
        "INSERT INTO checks (ts, category, name, ok, latency_ms, status_code, detail) VALUES (?,?,?,?,?,?,?)",
        (int(time.time()), category, name, 1 if ok else 0, latency_ms, status_code, detail[:2000]),
    )
    conn.commit()
    conn.close()

def save_system(cpu, ram, disk, sent_mb, recv_mb):
    conn = get_conn()
    conn.execute(
        "INSERT INTO system_metrics (ts, cpu, ram, disk, net_sent_mb, net_recv_mb) VALUES (?,?,?,?,?,?)",
        (int(time.time()), cpu, ram, disk, sent_mb, recv_mb),
    )
    conn.execute("DELETE FROM system_metrics WHERE id IN (SELECT id FROM system_metrics ORDER BY id DESC LIMIT -1 OFFSET 70000)")
    conn.commit()
    conn.close()

def save_live(down, up, pgw, pnet, papp, cpu, ram):
    conn = get_conn()
    conn.execute(
        "INSERT INTO live_metrics (ts, down_mbps, up_mbps, ping_gateway_ms, ping_internet_ms, ping_app_ms, cpu, ram) VALUES (?,?,?,?,?,?,?,?)",
        (int(time.time()), down, up, pgw, pnet, papp, cpu, ram),
    )
    conn.execute("DELETE FROM live_metrics WHERE id IN (SELECT id FROM live_metrics ORDER BY id DESC LIMIT -1 OFFSET 30000)")
    conn.commit()
    conn.close()

def last_status():
    conn = get_conn()
    rows = conn.execute("""
        SELECT * FROM checks WHERE id IN (
            SELECT MAX(id) FROM checks GROUP BY category, name
        ) ORDER BY category, name
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def history(name=None, hours=6, limit=500):
    conn = get_conn()
    since = int(time.time()) - hours * 3600
    if name:
        rows = conn.execute("SELECT * FROM checks WHERE name=? AND ts>=? ORDER BY ts ASC LIMIT ?", (name, since, limit)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM checks WHERE ts>=? ORDER BY ts ASC LIMIT ?", (since, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def system_history(hours=6, limit=1000):
    conn = get_conn()
    since = int(time.time()) - hours * 3600
    rows = conn.execute("SELECT * FROM system_metrics WHERE ts>=? ORDER BY ts ASC LIMIT ?", (since, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def live_history(hours=2, limit=1500):
    conn = get_conn()
    since = int(time.time()) - hours * 3600
    rows = conn.execute(
        """SELECT * FROM (
             SELECT * FROM live_metrics WHERE ts>=? ORDER BY ts DESC LIMIT ?
           ) ORDER BY ts ASC""",
        (since, limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
