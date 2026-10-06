# MiPro Monitoring 🖥️

Sistema liviano de monitoreo interno para el equipo de soporte.
Corre como **servidor web central**: lo instalas en un PC/servidor y todo el equipo accede desde el navegador (PC, tablet, celular) sin instalar nada.

## Qué monitorea (v1)
- **APIs y páginas internas**: status HTTP + latencia cada 30s, con gráfica tiempo real.
- **Servidor local**: CPU, RAM, disco, red cada 10s.
- **Automatizaciones**: archivos/logs, procesos Windows y jobs HTTP cada 60s.
- **Red y equipos**: escaneo bajo demanda por CIDR (ping + puertos + hostname).

Alertas v1: solo dashboard (en vivo por WebSocket). Telegram/Email se agrega en v2.

## Instalación (Windows)
```powershell
cd C:\MiPro\Monitoring
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Configurar objetivos
Edita `targets.yaml`:
- `http_targets`: url, expect_status
- `network.subnets`, `ports`
- `automations`: type file|http|process
- Se recarga solo cada 60s.

## Ejecutar
```powershell
uvicorn app.main:app --host 0.0.0.0 --port 8000
# abrir desde cualquier dispositivo en red: http://IP-del-servidor:8000
```

O doble clic en `run.bat`.

## Estructura
```
app/main.py -> FastAPI + scheduler + websocket
app/monitor/ -> http_check, network, system, automations
app/database.py -> SQLite historial para gráficas
static/index.html -> dashboard responsive + Chart.js
targets.yaml -> configuración editable
```

## Siguiente (v2 sugerido)
- Login básico + roles soporte
- Notificaciones Telegram/Teams
- Agente para PCs remotas (CPU/remoto)
- SNMP para switches/impresoras
- Exportar reportes PDF
