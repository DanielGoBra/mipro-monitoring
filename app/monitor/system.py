"""Métricas del servidor donde corre el monitor (CPU/RAM/Disco/Red)."""
import psutil

_last_net = None

def get_system():
    global _last_net
    cpu = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory().percent
    disk = psutil.disk_usage("/").percent if hasattr(psutil, "disk_usage") else 0
    try:
        disk = psutil.disk_usage("C:\\").percent
    except Exception:
        pass
    net = psutil.net_io_counters()
    sent_mb = round(net.bytes_sent / 1024 / 1024, 2)
    recv_mb = round(net.bytes_recv / 1024 / 1024, 2)
    return {"cpu": cpu, "ram": ram, "disk": disk, "net_sent_mb": sent_mb, "net_recv_mb": recv_mb}
