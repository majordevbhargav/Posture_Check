"""
Posture Console — web UI for the posture-check workflow.

New devices from ise_session_watcher.py's queue are now checked
AUTOMATICALLY in the background, using the stored common credential -
no click needed. A device only shows up in this page's "Needs
attention" list if its check actually failed, at which point you can
Retry (same stored credential), use different credentials for just
that device, or Skip it. Compliant and non-compliant results go
straight into the results log either way.

SECURITY NOTE (read before using outside a local POC): the password you
type in the browser (for a "different creds?" override) is sent to
this server in plaintext (fine over localhost HTTP for testing) and
passed to PowerShell as a command-line argument, which is briefly
visible to anything inspecting the process list while the check runs.
That's an acceptable tradeoff for a local POC, not for a shared/
production deployment — before then, swap this for a proper secret
store (Windows Credential Manager, DPAPI, a vault) rather than passing
plaintext around.

Install deps:
    pip install flask --break-system-packages

Run:
    set QUEUE_FILE=pending_devices.txt
    set PS_SCRIPT=posture_agent.ps1
    set POSTURE_SERVER=http://127.0.0.1:8000/api/v1/posture
    python posture_ui.py

Then open http://127.0.0.1:5000
"""

import os
import json
import time
import msvcrt
import threading
import subprocess
import datetime
from pathlib import Path

from flask import Flask, request, jsonify, Response

QUEUE_FILE = os.environ.get("PENDING_QUEUE_FILE", "pending_devices.txt")
PS_SCRIPT = os.environ.get("PS_SCRIPT", "posture_agent.ps1")
POSTURE_SERVER = os.environ.get("POSTURE_SERVER", "http://127.0.0.1:8000/api/v1/posture")
UI_PORT = int(os.environ.get("UI_PORT", "5000"))
AUTO_WORKER_POLL_SECONDS = float(os.environ.get("AUTO_WORKER_POLL_SECONDS", "3"))

# Written by ise_session_watcher.py — lets us show a device's MAC even
# when the compliance check itself errors out before it gets far enough
# to read the MAC directly off the device (e.g. a connection failure).
IP_MAC_MAP_FILE = os.environ.get("IP_MAC_MAP_FILE", "ip_mac_map.txt")

app = Flask(__name__)

# In-memory results log - resets if this server restarts. Fine for a POC
# console; swap for a real store if you need history to survive restarts.
RESULTS = []

# Devices that failed a check and need a human to look at them - either
# retry (same stored credential), retry with different credentials, or
# skip. This is deliberately SEPARATE from the watcher's queue file:
# devices land here only after failing once, and the auto-worker below
# never touches this list, so a broken device doesn't get silently
# retried forever in a loop - it waits for you.
NEEDS_ATTENTION = []
STATE_LOCK = threading.Lock()  # guards RESULTS and NEEDS_ATTENTION, shared
                                # between Flask request threads and the
                                # background auto-worker thread


def lookup_known_mac(ip: str):
    """Best-effort MAC lookup from the watcher's ip->mac map. Returns
    None if the file doesn't exist or has no entry for this IP."""
    path = Path(IP_MAC_MAP_FILE)
    if not path.exists():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        if "," not in line:
            continue
        k, v = line.split(",", 1)
        if k.strip() == ip:
            return v.strip()
    return None


# ---------------------------------------------------------------------------
# Queue helpers - same file format as posture_agent.ps1 / the watcher
#
# ise_session_watcher.py appends to this file independently, in a
# separate process, while this file's remove/requeue read-then-overwrite
# the whole thing. Without locking, a watcher append landing in that
# narrow window gets silently discarded by our overwrite - a device the
# watcher just found would simply vanish, no error anywhere. Both this
# file and the watcher now take the same advisory lock (byte 0 of the
# queue file) before touching it, so their reads/writes can't interleave.
# ---------------------------------------------------------------------------
def _locked(path: str):
    """Opens `path` for read/write and takes an exclusive lock on it for
    the life of the returned handle. Creates the file first if missing,
    since msvcrt.locking needs something to lock. Caller must close the
    handle (which also releases the lock) when done."""
    if not os.path.exists(path):
        open(path, "a", encoding="utf-8").close()
    f = open(path, "r+", encoding="utf-8")
    msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
    return f


def _unlock_close(f):
    f.seek(0)
    msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
    f.close()


def read_queue():
    path = Path(QUEUE_FILE)
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def remove_from_queue(ip: str):
    f = _locked(QUEUE_FILE)
    try:
        items = [line.strip() for line in f.read().splitlines() if line.strip()]
        items = [i for i in items if i != ip]
        f.seek(0)
        f.truncate()
        f.write("\n".join(items) + ("\n" if items else ""))
        return items
    finally:
        _unlock_close(f)


def requeue(ip: str):
    """Add an IP back to the SHARED FILE queue - only used for genuine
    infrastructure failures (timeout, PowerShell itself not runnable)
    where retrying automatically still makes sense. A real check
    failure (bad creds, connection refused, etc.) goes to
    NEEDS_ATTENTION instead - see add_needs_attention()."""
    f = _locked(QUEUE_FILE)
    try:
        items = [line.strip() for line in f.read().splitlines() if line.strip()]
        if ip not in items:
            items.append(ip)
        f.seek(0)
        f.truncate()
        f.write("\n".join(items) + ("\n" if items else ""))
        return items
    finally:
        _unlock_close(f)


def add_needs_attention(ip: str):
    with STATE_LOCK:
        if ip not in NEEDS_ATTENTION:
            NEEDS_ATTENTION.append(ip)
        return list(NEEDS_ATTENTION)


def remove_needs_attention(ip: str):
    with STATE_LOCK:
        if ip in NEEDS_ATTENTION:
            NEEDS_ATTENTION.remove(ip)
        return list(NEEDS_ATTENTION)


def get_needs_attention():
    with STATE_LOCK:
        return list(NEEDS_ATTENTION)


def append_result(entry: dict):
    with STATE_LOCK:
        RESULTS.append(entry)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")


def run_check(ip: str, username: str = None, password: str = None) -> dict:
    """Runs posture_agent.ps1 against one IP and returns the result entry
    (also appending it to RESULTS). On success (COMPLIANT/NON-COMPLIANT),
    that's the end of it. On any failure, the IP goes into
    NEEDS_ATTENTION so a human decides what happens next, rather than
    being retried automatically forever."""
    cmd = [
        "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", PS_SCRIPT,
        "-ComputerName", ip,
        "-PostureServer", POSTURE_SERVER,
    ]
    if username and password:
        cmd += ["-Username", username, "-PlainPassword", password]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        add_needs_attention(ip)
        entry = {"time": datetime.datetime.now().strftime("%H:%M:%S"), "ip": ip,
                  "mac": lookup_known_mac(ip), "status": "ERROR",
                  "detail": "Timed out waiting for the check to finish."}
        append_result(entry)
        return entry
    except Exception as e:
        # PowerShell itself not runnable, permissions error, etc.
        add_needs_attention(ip)
        entry = {"time": datetime.datetime.now().strftime("%H:%M:%S"), "ip": ip,
                  "mac": lookup_known_mac(ip), "status": "ERROR",
                  "detail": f"Unexpected error running the check: {e}"}
        append_result(entry)
        return entry

    parsed = None
    for line in proc.stdout.splitlines():
        if line.startswith("RESULT_JSON:"):
            try:
                parsed = json.loads(line[len("RESULT_JSON:"):])
            except json.JSONDecodeError:
                parsed = None

    if parsed is None:
        # Script didn't get far enough to emit a result line - surface
        # whatever it printed instead of failing silently.
        add_needs_attention(ip)
        detail = (proc.stderr or proc.stdout or "No output from the script.").strip()[-500:]
        entry = {"time": datetime.datetime.now().strftime("%H:%M:%S"), "ip": ip,
                  "mac": lookup_known_mac(ip), "status": "ERROR", "detail": detail}
    else:
        is_error = parsed.get("status") == "ERROR"
        if is_error:
            add_needs_attention(ip)
        entry = {
            "time": datetime.datetime.now().strftime("%H:%M:%S"),
            "ip": ip,
            "computer": parsed.get("computer"),
            "mac": parsed.get("mac") or lookup_known_mac(ip),
            "os": parsed.get("os"),
            "status": parsed.get("status"),
            "detail": parsed.get("detail"),
            "submitted": parsed.get("submitted"),
            "submitError": parsed.get("submitError"),
        }

    append_result(entry)
    return entry


def auto_worker():
    """Background loop: drains the watcher's queue file automatically,
    running each device with the stored common credential - no click
    needed. Only failures ever reach the UI (via NEEDS_ATTENTION)."""
    while True:
        try:
            pending = read_queue()
            if pending:
                ip = pending[0]
                remove_from_queue(ip)
                run_check(ip)
        except Exception:
            # Never let the background loop die - a bad iteration just
            # gets logged implicitly via the next poll's result, and the
            # loop keeps going.
            pass
        time.sleep(AUTO_WORKER_POLL_SECONDS)


@app.route("/api/needs_attention")
def api_needs_attention():
    return jsonify({"needs_attention": get_needs_attention()})


@app.route("/api/results")
def api_results():
    return jsonify({"results": RESULTS[-50:][::-1]})


@app.route("/api/skip", methods=["POST"])
def api_skip():
    data = request.get_json(force=True)
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "ip is required"}), 400
    remaining = remove_needs_attention(ip)
    append_result({
        "time": datetime.datetime.now().strftime("%H:%M:%S"),
        "ip": ip,
        "status": "SKIPPED",
        "detail": "Skipped - not checked.",
    })
    return jsonify({"needs_attention": remaining})


@app.route("/api/check", methods=["POST"])
def api_check():
    """Manual (re)run from the UI - either the plain "Run" retry (no
    creds passed -> stored common credential is used) or the "different
    creds?" override (both passed)."""
    data = request.get_json(force=True)
    ip = data.get("ip", "").strip()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not ip:
        return jsonify({"error": "ip is required"}), 400

    # It's being handled right now either way - clear it first so a
    # renewed failure below adds it back cleanly rather than being a
    # silent no-op against an item already in the list.
    remove_needs_attention(ip)

    run_check(ip, username or None, password or None)

    return jsonify({"needs_attention": get_needs_attention()})


# ---------------------------------------------------------------------------
# Frontend - single-page, no build step. Dark "network console" theme,
# since this is a straight swap for a terminal workflow.
# ---------------------------------------------------------------------------
INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="light only">
<title>ISE Posture Console</title>
<style>
  html { color-scheme: light only; }
  :root {
    --bg: #ffffff;
    --panel: #ffffff;
    --border: #e5e7eb;
    --border-soft: #f0f1f3;
    --text: #111318;
    --muted: #8a8f98;
    --green: #16a34a;
    --green-bg: #f0faf3;
    --red: #dc2626;
    --red-bg: #fef2f2;
    --blue: #2563eb;
    --gray-bg: #f7f7f8;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, "Segoe UI", Inter, Helvetica, Arial, sans-serif;
    font-size: 14px;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
  }
  .mono { font-family: "SFMono-Regular", Consolas, Menlo, monospace; }
  .wrap { max-width: 780px; margin: 0 auto; padding: 48px 20px 80px; }

  header {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    margin-bottom: 28px;
  }
  header h1 {
    font-size: 17px;
    font-weight: 600;
    letter-spacing: -0.01em;
    margin: 0;
    color: var(--text);
  }
  header .meta { font-size: 12px; color: var(--muted); }

  .search-bar { margin-bottom: 16px; }
  .search-bar input {
    width: 100%;
    font-family: inherit;
    background: #ffffff;
    border: 1px solid var(--border);
    color: var(--text);
    padding: 10px 12px;
    border-radius: 8px;
    font-size: 13px;
  }
  .search-bar input:focus { outline: none; border-color: var(--blue); }

  .panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    margin-bottom: 20px;
    overflow: hidden;
  }
  .panel-title {
    font-size: 12px;
    font-weight: 600;
    color: var(--muted);
    padding: 12px 18px;
    border-bottom: 1px solid var(--border-soft);
    display: flex;
    justify-content: space-between;
    background: var(--gray-bg);
  }
  .panel-body { padding: 0; }

  .row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 13px 18px;
    border-bottom: 1px solid var(--border-soft);
  }
  .row:last-child { border-bottom: none; }

  .dot {
    width: 7px; height: 7px; border-radius: 50%;
    background: var(--green);
    flex-shrink: 0;
  }

  .ip { color: var(--text); min-width: 118px; font-weight: 500; }
  .empty { color: var(--muted); padding: 24px 18px; font-size: 13px; }

  button {
    font-family: inherit;
    font-size: 12.5px;
    font-weight: 500;
    background: #ffffff;
    border: 1px solid var(--border);
    color: var(--text);
    padding: 6px 13px;
    border-radius: 6px;
    cursor: pointer;
  }
  button:hover { border-color: #c9ccd1; background: var(--gray-bg); }
  button.skip:hover { border-color: var(--red); color: var(--red); background: var(--red-bg); }
  button.run:hover { border-color: var(--blue); color: var(--blue); }
  button.override-link { border-color: transparent; background: transparent; color: var(--muted); font-size: 12px; text-decoration: underline; padding: 4px 4px; }
  button.override-link:hover { color: var(--text); }
  button.confirm { background: var(--text); border-color: var(--text); color: #fff; }
  button.confirm:hover { opacity: 0.85; background: var(--text); color: #fff; }
  button.cancel { border-color: transparent; color: var(--muted); }
  button.cancel:hover { border-color: var(--border); background: var(--gray-bg); color: var(--text); }
  button:disabled { opacity: 0.4; cursor: default; }

  .spacer { flex: 1; }

  .cred-form {
    display: none;
    gap: 8px;
    padding: 12px 18px 16px;
    border-bottom: 1px solid var(--border-soft);
    background: var(--gray-bg);
  }
  .cred-form.open { display: flex; align-items: center; flex-wrap: wrap; }
  .cred-form input {
    font-family: inherit;
    background: #fff;
    border: 1px solid var(--border);
    color: var(--text);
    padding: 7px 10px;
    border-radius: 6px;
    font-size: 13px;
  }
  .cred-form input:focus { outline: none; border-color: var(--blue); }

  .results .row { align-items: flex-start; }
  .status-badge {
    font-size: 11px;
    font-weight: 600;
    padding: 3px 9px;
    border-radius: 5px;
    min-width: 104px;
    text-align: center;
  }
  .status-COMPLIANT { background: var(--green-bg); color: var(--green); }
  .status-NON-COMPLIANT { background: var(--red-bg); color: var(--red); }
  .status-ERROR { background: var(--red-bg); color: var(--red); }
  .status-SKIPPED { background: var(--gray-bg); color: var(--muted); }

  .detail { color: var(--muted); font-size: 12.5px; }
  .time { color: var(--muted); font-size: 12px; min-width: 56px; }
  .mac {
    font-size: 11.5px;
    color: var(--text);
    background: var(--gray-bg);
    border: 1px solid var(--border);
    padding: 2px 8px;
    border-radius: 5px;
    white-space: nowrap;
  }

  footer { color: var(--muted); font-size: 11.5px; text-align: center; margin-top: 24px; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>ISE Posture Console</h1>
    <div class="meta" id="server-label"></div>
  </header>

  <div class="search-bar">
    <input type="text" id="search-input" class="mono" placeholder="Filter by IP, hostname, or MAC..." autocomplete="off" />
  </div>

  <div class="panel">
    <div class="panel-title">
      <span>Needs attention</span>
      <span id="pending-count">0</span>
    </div>
    <div class="panel-body" id="queue-list">
      <div class="empty">Nothing needs attention. New devices are checked automatically as they connect.</div>
    </div>
  </div>

  <div class="panel results">
    <div class="panel-title"><span>Results log</span><span id="results-count">0</span></div>
    <div class="panel-body" id="results-list">
      <div class="empty">Nothing checked yet.</div>
    </div>
  </div>

  <footer>Devices are checked automatically as they connect &middot; polling every 4s</footer>
</div>

<script>
const serverLabel = document.getElementById('server-label');
serverLabel.textContent = 'posture server: ' + (window.__POSTURE_SERVER__ || '');

let formOpenFor = null; // ip of the currently open cred-form, or null
let searchTerm = '';    // lowercased, updated as the user types
let currentPending = [];
let currentResults = [];

async function fetchJSON(url, opts) {
  const res = await fetch(url, opts);
  return res.json();
}

function applyPendingFilter(list) {
  if (!searchTerm) return list;
  return list.filter(ip => ip.toLowerCase().includes(searchTerm));
}

function applyResultsFilter(list) {
  if (!searchTerm) return list;
  return list.filter(r =>
    (r.ip || '').toLowerCase().includes(searchTerm) ||
    (r.computer || '').toLowerCase().includes(searchTerm) ||
    (r.mac || '').toLowerCase().includes(searchTerm)
  );
}

function esc(s) {
  // Basic HTML-escaping for anything interpolated into innerHTML below.
  // These values come from ISE's own session data / the check scripts,
  // not directly from an attacker, but there's no reason to skip this.
  return String(s ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function rowTemplate(ip) {
  const safeIp = esc(ip);
  const div = document.createElement('div');
  div.className = 'device';
  div.innerHTML = `
    <div class="row">
      <span class="dot"></span>
      <span class="ip mono">${safeIp}</span>
      <span class="spacer"></span>
      <button class="run" data-ip="${safeIp}">Retry</button>
      <button class="override-link" data-ip="${safeIp}">different creds?</button>
      <button class="skip" data-ip="${safeIp}">Skip</button>
    </div>
    <div class="cred-form" data-ip="${safeIp}">
      <input type="text" class="username" placeholder="Username (e.g. Administrator)" />
      <input type="password" class="password" placeholder="Password" />
      <button class="confirm" data-ip="${safeIp}">Confirm &#9656;</button>
      <button class="cancel" data-ip="${safeIp}">Cancel</button>
    </div>
  `;
  return div;
}

function renderQueue(pending) {
  const list = document.getElementById('queue-list');
  document.getElementById('pending-count').textContent = pending.length;
  if (pending.length === 0) {
    list.innerHTML = '<div class="empty">Nothing needs attention. New devices are checked automatically as they connect.</div>';
    return;
  }
  list.innerHTML = '';
  pending.forEach(ip => list.appendChild(rowTemplate(ip)));
}

function renderResults(results) {
  const list = document.getElementById('results-list');
  document.getElementById('results-count').textContent = results.length;
  if (results.length === 0) {
    list.innerHTML = '<div class="empty">Nothing checked yet.</div>';
    return;
  }
  list.innerHTML = '';
  results.forEach(r => {
    const badgeClass = 'status-' + esc(r.status || 'ERROR');
    const detailBits = [];
    if (r.computer) detailBits.push(esc(r.computer));
    if (r.detail) detailBits.push(esc(r.detail));
    if (r.submitted === false) detailBits.push('(not submitted to ISE: ' + esc(r.submitError || 'unknown error') + ')');
    const needsMac = (r.status === 'ERROR' || r.status === 'NON-COMPLIANT');
    const macBadge = needsMac
      ? `<span class="mac mono">MAC: ${esc(r.mac || 'unknown')}</span>`
      : (r.mac ? `<span class="mac mono">MAC: ${esc(r.mac)}</span>` : '');
    const row = document.createElement('div');
    row.className = 'row';
    row.innerHTML = `
      <span class="time">${esc(r.time)}</span>
      <span class="ip mono">${esc(r.ip)}</span>
      <span class="status-badge ${badgeClass}">${esc(r.status || 'ERROR')}</span>
      ${macBadge}
      <span class="detail">${detailBits.join(' &middot; ')}</span>
    `;
    list.appendChild(row);
  });
}

async function refreshQueue() {
  const data = await fetchJSON('/api/needs_attention');
  currentPending = data.needs_attention;
  if (formOpenFor) return; // don't rebuild the list out from under an open form
  renderQueue(applyPendingFilter(currentPending));
}

async function refreshResults() {
  const data = await fetchJSON('/api/results');
  currentResults = data.results;
  renderResults(applyResultsFilter(currentResults));
}

document.addEventListener('click', async (e) => {
  const ip = e.target.dataset.ip;
  if (!ip) return;

  if (e.target.classList.contains('run')) {
    // Retry with the stored common credential (posture_agent.ps1 loads
    // it automatically). Only reachable here because this device
    // already failed once - first attempts happen automatically in
    // the background, before anything shows up in this list.
    e.target.disabled = true;
    e.target.textContent = 'Retrying...';
    const data = await fetchJSON('/api/check', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ip})
    });
    currentPending = data.needs_attention;
    renderQueue(applyPendingFilter(currentPending));
    refreshResults();
  }

  if (e.target.classList.contains('override-link')) {
    document.querySelectorAll('.cred-form').forEach(f => f.classList.remove('open'));
    const form = document.querySelector(`.cred-form[data-ip="${ip}"]`);
    form.classList.add('open');
    form.querySelector('.username').focus();
    formOpenFor = ip;
  }

  if (e.target.classList.contains('cancel')) {
    document.querySelector(`.cred-form[data-ip="${ip}"]`).classList.remove('open');
    formOpenFor = null;
  }

  if (e.target.classList.contains('skip')) {
    e.target.disabled = true;
    const data = await fetchJSON('/api/skip', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ip})
    });
    currentPending = data.needs_attention;
    renderQueue(applyPendingFilter(currentPending));
    refreshResults();
  }

  if (e.target.classList.contains('confirm')) {
    // The override path — only used when "different creds?" was clicked.
    const form = document.querySelector(`.cred-form[data-ip="${ip}"]`);
    const username = form.querySelector('.username').value.trim();
    const password = form.querySelector('.password').value;
    if (!username || !password) { return; }
    e.target.disabled = true;
    e.target.textContent = 'Running...';
    const data = await fetchJSON('/api/check', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ip, username, password})
    });
    formOpenFor = null;
    currentPending = data.needs_attention;
    renderQueue(applyPendingFilter(currentPending));
    refreshResults();
  }
});

document.getElementById('search-input').addEventListener('input', (e) => {
  searchTerm = e.target.value.trim().toLowerCase();
  if (!formOpenFor) renderQueue(applyPendingFilter(currentPending));
  renderResults(applyResultsFilter(currentResults));
});

refreshQueue();
refreshResults();
setInterval(refreshQueue, 4000);
setInterval(refreshResults, 4000);
</script>
</body>
</html>
"""


if __name__ == "__main__":
    print(f"Posture Console at http://127.0.0.1:{UI_PORT}")
    print(f"Queue file: {QUEUE_FILE}")
    print(f"PS script:  {PS_SCRIPT}")
    print(f"Posture server: {POSTURE_SERVER}")
    print("Auto-worker running: new devices are checked automatically in the background.")
    threading.Thread(target=auto_worker, daemon=True).start()
    app.run(host="127.0.0.1", port=UI_PORT, debug=False, threaded=True)