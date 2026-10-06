# Despliegue en servidor (equipo de soporte + monitoreo 24/7 de APIs)

Objetivo: la app corre **en el servidor** y todo soporte entra por navegador.
El servidor es quien hace ping/HTTP a las APIs (no cada PC).

## 1. Requisitos del servidor
- Windows Server 2019+ o Linux (Ubuntu 22.04+) con Python 3.11+
- Puerto 8000 abierto en firewall hacia la LAN (o 443 con proxy)
- Opcional para seguridad total: Npcap (Windows), nmap, Wireshark/tshark
- Variable opcional: `SHODAN_API_KEY` para threat intel externa

## 2. Instalación
```powershell
cd C:\MiPro\Monitoring
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy targets.yaml targets.produccion.yaml  # ajusta URLs/subred del servidor
```

## 3a. Windows como servicio (NSSM, recomendado)
```powershell
# https://nssm.cc/download
nssm install MiProMonitoring "C:\MiPro\Monitoring\.venv\Scripts\python.exe" "-m uvicorn app.main:app --host 0.0.0.0 --port 8000"
nssm set MiProMonitoring AppDirectory "C:\MiPro\Monitoring"
nssm set MiProMonitoring AppStdout "C:\MiPro\Monitoring\service.log"
nssm start MiProMonitoring
```

## 3b. Linux (systemd)
```ini
# /etc/systemd/system/mipro.service
[Unit]
Description=MiPro Monitoring
After=network.target
[Service]
WorkingDirectory=/opt/Monitoring
ExecStart=/opt/Monitoring/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1
Restart=always
Environment=SHODAN_API_KEY=
[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl enable --now mipro
```

## 3c. Docker
```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```
```bash
docker build -t mipro .
docker run -d -p 8000:8000 --restart always --name mipro mipro
```

## 4. Acceso del equipo
- `http://IP-SERVIDOR:8000` desde cualquier PC/celular en red
- Con IIS/Nginx reverso + HTTPS se publica como `https://monitoreo.inklusiva.co`

## 5. Notas de monitoreo en servidor
- Los pings/latencias se miden **desde el servidor**: ubícalo en la misma VLAN principal (150) para ver los 27 equipos.
- SNMP/SSH al router (Netmiko/NAPALM) se configura una sola vez en el servidor.
- Backups: basta copiar `monitoring.db` + `targets.yaml`.
