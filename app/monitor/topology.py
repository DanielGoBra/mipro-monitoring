"""Topología a partir de los inventarios escaneados.

Capa 3: Internet, gateway por segmento, segmento.
Capa 2: si un switch entrega su tabla de reenvío por SNMP, cada equipo cuelga del puerto
con menos MAC donde aparece (puerto de acceso); los demás quedan en el segmento.
"""
import ipaddress

INFRA = ("gateway", "firewall")


def _gw_of(hosts, cidr):
    for h in hosts:
        if h.get("role") in INFRA:
            return h
    try:
        first = str(next(ipaddress.ip_network(cidr, strict=False).hosts()))
    except Exception:
        return None
    return next((h for h in hosts if h.get("ip") == first), None)


def build(nets):
    """nets: {cidr: [host, ...]} -> {nodes, links, subnets}."""
    nodes, links = [], []
    by_id = {}

    def add(node):
        if node["id"] in by_id:
            return by_id[node["id"]]
        by_id[node["id"]] = node
        nodes.append(node)
        return node

    def host_node(h, parent):
        return {
            "id": "h:" + h["ip"], "kind": h.get("role") or "unknown", "label": h.get("hostname") if h.get("hostname") not in ("-", "") else h["ip"],
            "ip": h["ip"], "mac": h.get("mac"), "vendor": h.get("vendor"), "type": h.get("device_type"),
            "online": h.get("online", True), "latency": h.get("latency_ms"), "subnet": h.get("subnet"),
            "state": ((h.get("physical") or {}).get("state")) or ("ok" if h.get("online", True) else "fail"),
            "summary": (h.get("physical") or {}).get("summary") or "", "parent": parent,
            "h": {k: v for k, v in h.items() if k != "fdb"},
        }

    add({"id": "internet", "kind": "cloud", "label": "Internet", "parent": None})
    routers = {}
    subnets = []
    all_hosts = []
    for cidr, hosts in nets.items():
        hosts = hosts or []
        all_hosts += hosts
        gw = _gw_of(hosts, cidr)
        if gw:
            key = gw.get("mac") if gw.get("mac") not in (None, "", "-") else gw["ip"]
            if key not in routers:
                rn = host_node(gw, "internet")
                rn["id"] = "r:" + key
                rn["kind"] = gw.get("role") if gw.get("role") in INFRA else "gateway"
                rn["ips"] = [gw["ip"]]
                routers[key] = add(rn)
                links.append({"a": "internet", "b": rn["id"], "kind": "wan"})
            else:
                routers[key].setdefault("ips", []).append(gw["ip"])
            rid = routers[key]["id"]
        else:
            rid = "internet"
        seg = add({"id": "s:" + cidr, "kind": "segment", "label": cidr, "subnet": cidr, "parent": rid,
                   "count": len(hosts), "online": sum(1 for h in hosts if h.get("online", True))})
        links.append({"a": rid, "b": seg["id"], "kind": "trunk", "label": gw["ip"] if gw else ""})
        subnets.append({"cidr": cidr, "gateway": gw["ip"] if gw else None, "count": len(hosts)})

    gw_ips = {ip for r in routers.values() for ip in r.get("ips", [])}
    switches = [h for h in all_hosts if h.get("role") == "switch"]
    mac_to_sw = {}
    for sw in switches:
        fdb = sw.get("fdb") or {}
        per_port = {}
        for mac, port in fdb.items():
            per_port[port] = per_port.get(port, 0) + 1
        for mac, port in fdb.items():
            n = per_port.get(port, 99)
            cur = mac_to_sw.get(mac)
            if cur is None or n < cur[2]:
                mac_to_sw[mac] = (sw["ip"], port, n)

    for h in all_hosts:
        if h["ip"] in gw_ips:
            continue
        seg_id = "s:" + (h.get("subnet") or "")
        parent, port = seg_id, None
        hit = mac_to_sw.get((h.get("mac") or "").lower())
        if hit and hit[0] != h["ip"] and hit[2] <= 3:
            parent, port = "h:" + hit[0], hit[1]
        n = add(host_node(h, parent))
        if port is not None:
            n["port"] = port
        links.append({"a": parent, "b": n["id"], "kind": "access" if port is not None else "logical",
                      "label": f"p{port}" if port is not None else ""})

    for sw in switches:
        sid = "h:" + sw["ip"]
        node = by_id.get(sid)
        if not node or not node["parent"].startswith("s:"):
            continue
        hit = mac_to_sw.get((sw.get("mac") or "").lower())
        if hit and hit[0] != sw["ip"]:
            for l in links:
                if l["b"] == sid:
                    l["a"], l["kind"], l["label"] = "h:" + hit[0], "trunk", f"p{hit[1]}"
            node["parent"] = "h:" + hit[0]

    return {"nodes": nodes, "links": links, "subnets": subnets,
            "l2": bool(mac_to_sw), "switches_snmp": sum(1 for s in switches if s.get("fdb"))}
