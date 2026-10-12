"""FastAPI + WebSocket live dashboard for ebpf-netsec."""

from __future__ import annotations

import asyncio
from dataclasses import asdict
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

from ebpf_netsec.sensors.bpftrace_runner import BpftraceRunner
from ebpf_netsec.storage.db import EventDB
from ebpf_netsec.detect.beaconing import detect_beacons
from ebpf_netsec.detect.dns_tunnel import detect_dns_tunnels
from ebpf_netsec.models import TcpConnectEvent, DnsQueryEvent


class ConnectionManager:
    """Tracks live WebSocket clients."""

    def __init__(self):
        self.clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self.clients.add(ws)

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            self.clients.discard(ws)

    async def broadcast(self, message: dict):
        async with self._lock:
            dead = []
            for ws in self.clients:
                try:
                    await ws.send_json(message)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self.clients.discard(ws)


class SensorPipeline:
    """Runs bpftrace in a background thread and pushes events to asyncio."""

    def __init__(
        self,
        script: str,
        db: EventDB,
        loop: asyncio.AbstractEventLoop,
        on_event,
        detect_interval: int = 15,
        detect_window: int = 5,
    ):
        self.script = script
        self.db = db
        self.loop = loop
        self.on_event = on_event
        self.detect_interval = detect_interval
        self.detect_window = detect_window
        self.runner = BpftraceRunner(script)
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.seen_beacons: set[tuple] = set()
        self.seen_tunnels: set[tuple] = set()

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self.runner.stop()

    def _run(self):
        self.runner.start()
        last_detect = 0.0
        try:
            for evt in self.runner.events():
                if self._stop.is_set():
                    break
                # Store in SQLite (thread-safe via lock)
                if isinstance(evt, TcpConnectEvent):
                    self.db.insert_event(evt)
                else:
                    self.db.insert_dns(evt)

                # Push to async consumers
                asyncio.run_coroutine_threadsafe(
                    self.on_event(evt), self.loop
                )

                # Periodic detection
                now = time.time()
                if now - last_detect >= self.detect_interval:
                    last_detect = now
                    self._run_detectors()
        except Exception as e:
            print(f"[sensor] error: {e}")

    def _run_detectors(self):
        # Beacons
        try:
            for b in detect_beacons(
                self.db.recent_events(minutes=self.detect_window),
                min_count=5,
            ):
                key = (b.comm, b.daddr, b.dport)
                if b.score >= 4.0 and key not in self.seen_beacons:
                    self.seen_beacons.add(key)
                    self.db.insert_beacon(b)
                    print(f"[DETECT] BEACON {b.comm} -> {b.daddr}:{b.dport} score={b.score} count={b.count}")
                    asyncio.run_coroutine_threadsafe(
                        self.on_event({"type": "beacon", "data": asdict(b)}),
                        self.loop,
                    )
        except Exception as e:
            print(f"[detect beacon] {e}")

        # DNS tunnels
        try:
            for t in detect_dns_tunnels(
                self.db.recent_dns(minutes=self.detect_window),
                min_count=5,
            ):
                key = (t.comm, t.server)
                if t.score >= 4.0 and key not in self.seen_tunnels:
                    self.seen_tunnels.add(key)
                    self.db.insert_dns_tunnel(t)
                    print(f"[DETECT] TUNNEL {t.comm} -> {t.server} score={t.score} count={t.count}")
                    asyncio.run_coroutine_threadsafe(
                        self.on_event({"type": "tunnel", "data": asdict(t)}),
                        self.loop,
                    )
        except Exception as e:
            print(f"[detect tunnel] {e}")


# ---------------------------------------------------------------------------
# FastAPI app factory
# ---------------------------------------------------------------------------

def create_app(
    script: str = "ebpf/tcpconnect.bt",
    db_path: str = "data/events.db",
    detect_interval: int = 15,
) -> FastAPI:

    manager = ConnectionManager()
    db = EventDB(db_path)
    state: dict = {"beacons": 0, "tunnels": 0, "tcp": 0, "dns": 0}
    pipeline_holder: dict = {}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        loop = asyncio.get_running_loop()

        async def on_event(evt):
            if isinstance(evt, dict):
                # Structured detection event
                if evt["type"] == "beacon":
                    state["beacons"] += 1
                elif evt["type"] == "tunnel":
                    state["tunnels"] += 1
                await manager.broadcast(evt)
                return

            if isinstance(evt, TcpConnectEvent):
                state["tcp"] += 1
                await manager.broadcast({
                    "type": "tcp",
                    "data": {
                        "ts": evt.timestamp.strftime("%H:%M:%S"),
                        "pid": evt.pid,
                        "comm": evt.comm,
                        "daddr": evt.daddr,
                        "dport": evt.dport,
                    },
                })
            elif isinstance(evt, DnsQueryEvent):
                state["dns"] += 1
                await manager.broadcast({
                    "type": "dns",
                    "data": {
                        "ts": evt.timestamp.strftime("%H:%M:%S"),
                        "pid": evt.pid,
                        "comm": evt.comm,
                        "server": evt.server,
                        "size": evt.size,
                    },
                })

        pipeline = SensorPipeline(
            script=script, db=db, loop=loop,
            on_event=on_event,
            detect_interval=detect_interval,
        )
        pipeline.start()
        pipeline_holder["pipeline"] = pipeline

        try:
            yield
        finally:
            pipeline.stop()
            db.close()

    app = FastAPI(title="ebpf-netsec", lifespan=lifespan)

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return HTMLResponse(INDEX_HTML)

    @app.get("/stats")
    async def stats():
        return state

    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket):
        await manager.connect(ws)
        try:
            # Send recent history immediately
            recent_events = db.recent_events(minutes=5)[-50:]
            for e in recent_events:
                await ws.send_json({
                    "type": "tcp",
                    "data": {
                        "ts": e.timestamp.strftime("%H:%M:%S"),
                        "pid": e.pid, "comm": e.comm,
                        "daddr": e.daddr, "dport": e.dport,
                    },
                })
            recent_dns = db.recent_dns(minutes=5)[-30:]
            for q in recent_dns:
                await ws.send_json({
                    "type": "dns",
                    "data": {
                        "ts": q.timestamp.strftime("%H:%M:%S"),
                        "pid": q.pid, "comm": q.comm,
                        "server": q.server, "size": q.size,
                    },
                })
            # Keep connection alive
            while True:
                await ws.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            await manager.disconnect(ws)

    return app


# ---------------------------------------------------------------------------
# Inline HTML dashboard
# ---------------------------------------------------------------------------

INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ebpf-netsec — Live Dashboard</title>
<style>
  * { box-sizing: border-box; }
  body {
    margin: 0; font-family: 'Segoe UI', Roboto, sans-serif;
    background: #0d1117; color: #e6edf3; font-size: 13px;
  }
  header {
    padding: 12px 20px; background: #161b22;
    border-bottom: 1px solid #30363d;
    display: flex; justify-content: space-between; align-items: center;
  }
  header h1 { font-size: 16px; margin: 0; color: #58a6ff; font-weight: 600; }
  .stats { display: flex; gap: 24px; }
  .stat { text-align: right; }
  .stat b { display: block; font-size: 18px; color: #e6edf3; }
  .stat span { font-size: 11px; color: #8b949e; text-transform: uppercase; }
  .live { color: #3fb950; font-weight: 600; }
  .grid {
    display: grid; grid-template-columns: 1fr 1fr;
    gap: 16px; padding: 16px;
  }
  .card {
    background: #161b22; border: 1px solid #30363d;
    border-radius: 6px; overflow: hidden;
  }
  .card h2 {
    margin: 0; padding: 10px 14px; font-size: 12px;
    background: #1c2129; border-bottom: 1px solid #30363d;
    color: #8b949e; text-transform: uppercase; letter-spacing: 0.5px;
  }
  table { width: 100%; border-collapse: collapse; }
  th, td {
    padding: 6px 12px; text-align: left;
    border-bottom: 1px solid #21262d; font-size: 12px;
    font-family: 'JetBrains Mono', Menlo, monospace;
  }
  th { color: #8b949e; font-weight: 500; background: #1c2129; }
  tr:hover { background: #1c2129; }
  .proc { color: #79c0ff; }
  .ip { color: #7ee787; }
  .port { color: #ffa657; }
  .alerts { padding: 16px; }
  .alert {
    background: #2d1117; border-left: 3px solid #f85149;
    padding: 10px 14px; border-radius: 4px; margin-bottom: 8px;
    font-family: monospace; font-size: 12px;
  }
  .alert .tag {
    background: #f85149; color: #fff; padding: 2px 6px;
    border-radius: 3px; font-size: 10px; font-weight: 700;
    margin-right: 8px;
  }
  .alert .score { color: #f85149; font-weight: 700; }
  .alert .detail { color: #8b949e; margin-top: 4px; font-size: 11px; }
  .empty { padding: 30px; text-align: center; color: #484f58; }
  .scroll { max-height: 320px; overflow-y: auto; }
  canvas { display: block; padding: 12px; }
</style>
</head>
<body>

<header>
  <h1>🛡️ ebpf-netsec  <span class="live">● LIVE</span></h1>
  <div class="stats">
    <div class="stat"><b id="s-tcp">0</b><span>TCP</span></div>
    <div class="stat"><b id="s-dns">0</b><span>DNS</span></div>
    <div class="stat"><b id="s-beacon">0</b><span>Beacons</span></div>
    <div class="stat"><b id="s-tunnel">0</b><span>Tunnels</span></div>
  </div>
</header>

<div class="grid">
  <div class="card">
    <h2>Outbound TCP Connections</h2>
    <div class="scroll">
      <table>
        <thead><tr><th>Time</th><th>PID</th><th>Process</th><th>Dst</th><th>Port</th></tr></thead>
        <tbody id="tcp-body"></tbody>
      </table>
    </div>
  </div>

  <div class="card">
    <h2>DNS Queries</h2>
    <div class="scroll">
      <table>
        <thead><tr><th>Time</th><th>PID</th><th>Process</th><th>Server</th><th>Size</th></tr></thead>
        <tbody id="dns-body"></tbody>
      </table>
    </div>
  </div>

  <div class="card" style="grid-column: 1 / -1;">
    <h2>Detection Alerts</h2>
    <div class="alerts" id="alerts">
      <div class="empty">No alerts yet — watching...</div>
    </div>
  </div>
</div>

<script>
const tcpBody = document.getElementById('tcp-body');
const dnsBody = document.getElementById('dns-body');
const alertsBox = document.getElementById('alerts');
let alertCount = 0;

function addRow(tbody, cells, max = 40) {
  const tr = document.createElement('tr');
  tr.innerHTML = cells.join('');
  tbody.insertBefore(tr, tbody.firstChild);
  while (tbody.children.length > max) {
    tbody.removeChild(tbody.lastChild);
  }
}

function flash(el) {
  el.style.transition = 'background 0.4s';
  el.style.background = '#1f6feb30';
  setTimeout(() => el.style.background = '', 400);
}

const ws = new WebSocket(`ws://${location.host}/ws`);

ws.onmessage = (ev) => {
  const msg = JSON.parse(ev.data);

  if (msg.type === 'tcp') {
    const d = msg.data;
    addRow(tcpBody, [
      `<td>${d.ts}</td>`,
      `<td>${d.pid}</td>`,
      `<td class="proc">${d.comm}</td>`,
      `<td class="ip">${d.daddr}</td>`,
      `<td class="port">${d.dport}</td>`,
    ]);
    document.getElementById('s-tcp').textContent =
      (parseInt(document.getElementById('s-tcp').textContent) + 1);
    flash(tcpBody.firstChild);
  }

  else if (msg.type === 'dns') {
    const d = msg.data;
    addRow(dnsBody, [
      `<td>${d.ts}</td>`,
      `<td>${d.pid}</td>`,
      `<td class="proc">${d.comm}</td>`,
      `<td class="ip">${d.server}</td>`,
      `<td class="port">${d.size}</td>`,
    ]);
    document.getElementById('s-dns').textContent =
      (parseInt(document.getElementById('s-dns').textContent) + 1);
    flash(dnsBody.firstChild);
  }

  else if (msg.type === 'beacon') {
    const d = msg.data;
    document.getElementById('s-beacon').textContent =
      (parseInt(document.getElementById('s-beacon').textContent) + 1);
    addAlert('BEACON', `
      <b>${d.comm}</b> → <b>${d.daddr}:${d.dport}</b>
      <span class="score">score ${d.score}</span>
      <div class="detail">
        count=${d.count}  mean_interval=${d.mean_interval}s
        jitter=${d.jitter_ratio}  stddev=${d.stddev_interval}s
      </div>
    `);
  }

  else if (msg.type === 'tunnel') {
    const d = msg.data;
    document.getElementById('s-tunnel').textContent =
      (parseInt(document.getElementById('s-tunnel').textContent) + 1);
    addAlert('DNS TUNNEL', `
      <b>${d.comm}</b> → <b>${d.server}</b>
      <span class="score">score ${d.score}</span>
      <div class="detail">
        count=${d.count}  mean_size=${d.mean_size}B
        max_size=${d.max_size}B
      </div>
    `);
  }
};

function addAlert(tag, html) {
  if (alertCount === 0) alertsBox.innerHTML = '';
  alertCount++;
  const div = document.createElement('div');
  div.className = 'alert';
  div.innerHTML = `<span class="tag">${tag}</span>${html}`;
  alertsBox.insertBefore(div, alertsBox.firstChild);
  while (alertsBox.children.length > 20) {
    alertsBox.removeChild(alertsBox.lastChild);
  }
}

ws.onclose = () => {
  document.querySelector('.live').textContent = '● DISCONNECTED';
  document.querySelector('.live').style.color = '#f85149';
};
</script>
</body>
</html>
"""
