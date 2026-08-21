"""
Posture Console — web UI for the posture-check workflow, so you don't
have to type commands in a terminal each time.

Reads/writes the same pending_devices.txt queue that
ise_session_watcher.py fills and posture_agent.ps1 drains, and runs
posture_agent.ps1 for you when you click "Run" on a device, prompting
for username/password right there on the page instead of the console.

SECURITY NOTE (read before using outside a local POC): the password you
type in the browser is sent to this server in plaintext (fine over
localhost HTTP for testing) and passed to PowerShell as a command-line
argument, which is briefly visible to anything inspecting the process
list while the check runs. That's an acceptable tradeoff for a local
POC, not for a shared/production deployment — before then, swap this
for a proper secret store (Windows Credential Manager, DPAPI, a vault)
rather than passing plaintext around.

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
import msvcrt
import subprocess
import datetime
from pathlib import Path

from flask import Flask, request, jsonify, Response

QUEUE_FILE = os.environ.get("PENDING_QUEUE_FILE", "pending_devices.txt")
PS_SCRIPT = os.environ.get("PS_SCRIPT", "posture_agent.ps1")
POSTURE_SERVER = os.environ.get("POSTURE_SERVER", "http://127.0.0.1:8000/api/v1/posture")
UI_PORT = int(os.environ.get("UI_PORT", "5000"))

# Written by ise_session_watcher.py — lets us show a device's MAC even
# when the compliance check itself errors out before it gets far enough
# to read the MAC directly off the device (e.g. a connection failure).
IP_MAC_MAP_FILE = os.environ.get("IP_MAC_MAP_FILE", "ip_mac_map.txt")

app = Flask(__name__)

# In-memory results log - resets if this server restarts. Fine for a POC
# console; swap for a real store if you need history to survive restarts.
RESULTS = []


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
    """Add an IP back to the queue (e.g. after a failed check), skipping
    a duplicate if it's somehow already back in there."""
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


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")


@app.route("/api/queue")
def api_queue():
    return jsonify({"pending": read_queue()})


@app.route("/api/results")
def api_results():
    return jsonify({"results": RESULTS[-50:][::-1]})


@app.route("/api/skip", methods=["POST"])
def api_skip():
    data = request.get_json(force=True)
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "ip is required"}), 400
    pending = remove_from_queue(ip)
    RESULTS.append({
        "time": datetime.datetime.now().strftime("%H:%M:%S"),
        "ip": ip,
        "status": "SKIPPED",
        "detail": "Skipped from the queue, not checked.",
    })
    return jsonify({"pending": pending})


@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json(force=True)
    ip = data.get("ip", "").strip()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not ip or not username or not password:
        return jsonify({"error": "ip, username, and password are all required"}), 400

    # Consider it claimed the moment a check starts, same as the CLI does.
    remove_from_queue(ip)

    cmd = [
        "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", PS_SCRIPT,
        "-ComputerName", ip,
        "-Username", username,
        "-PlainPassword", password,
        "-PostureServer", POSTURE_SERVER,
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        pending = requeue(ip)
        entry = {"time": datetime.datetime.now().strftime("%H:%M:%S"), "ip": ip,
                  "status": "ERROR", "detail": "Timed out waiting for the check to finish. Re-queued for retry."}
        RESULTS.append(entry)
        return jsonify({"result": entry, "pending": pending})
    except Exception as e:
        # Anything else - PowerShell not found, a permissions error, etc.
        # Without this, the device was already removed from the queue
        # above and would be lost for good: it's already in seen_macs.txt
        # so the watcher would never queue it again either. Always requeue
        # here rather than let an unexpected error make a device vanish.
        pending = requeue(ip)
        entry = {"time": datetime.datetime.now().strftime("%H:%M:%S"), "ip": ip,
                  "status": "ERROR", "detail": f"Unexpected error running the check: {e} (re-queued for retry)"}
        RESULTS.append(entry)
        return jsonify({"result": entry, "pending": pending})

    parsed = None
    for line in proc.stdout.splitlines():
        if line.startswith("RESULT_JSON:"):
            try:
                parsed = json.loads(line[len("RESULT_JSON:"):])
            except json.JSONDecodeError:
                parsed = None

    if parsed is None:
        # Script didn't get far enough to emit a result line - surface
        # whatever it printed instead of failing silently, and put the
        # IP back in the queue so it can be retried later. Still try to
        # show the MAC, via the watcher's ip->mac map, since the check
        # never got far enough to read it directly off the device.
        pending = requeue(ip)
        detail = (proc.stderr or proc.stdout or "No output from the script.").strip()[-500:]
        entry = {"time": datetime.datetime.now().strftime("%H:%M:%S"), "ip": ip,
                  "mac": lookup_known_mac(ip),
                  "status": "ERROR", "detail": detail + " (re-queued for retry)"}
    else:
        # A connection/auth failure inside the script also reports as
        # status "ERROR" - same treatment, back in the queue. The script
        # usually can't read the device's MAC on a connection failure
        # (it never got that far), so fall back to the watcher's
        # ip->mac map — ISE already told us the MAC when the session
        # first appeared, no reason to lose it here.
        pending = requeue(ip) if parsed.get("status") == "ERROR" else read_queue()
        entry = {
            "time": datetime.datetime.now().strftime("%H:%M:%S"),
            "ip": ip,
            "computer": parsed.get("computer"),
            "mac": parsed.get("mac") or lookup_known_mac(ip),
            "os": parsed.get("os"),
            "status": parsed.get("status"),
            "detail": parsed.get("detail") + (" (re-queued for retry)" if parsed.get("status") == "ERROR" else ""),
            "submitted": parsed.get("submitted"),
            "submitError": parsed.get("submitError"),
        }

    RESULTS.append(entry)
    return jsonify({"result": entry, "pending": pending})


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
      <span>Pending devices</span>
      <span id="pending-count">0</span>
    </div>
    <div class="panel-body" id="queue-list">
      <div class="empty">No devices pending. Waiting on ise_session_watcher.py...</div>
    </div>
  </div>

  <div class="panel results">
    <div class="panel-title"><span>Results log</span><span id="results-count">0</span></div>
    <div class="panel-body" id="results-list">
      <div class="empty">Nothing checked yet.</div>
    </div>
  </div>

  <footer>Polling every 4s &middot; queue file: pending_devices.txt</footer>
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

function rowTemplate(ip) {
  const div = document.createElement('div');
  div.className = 'device';
  div.innerHTML = `
    <div class="row">
      <span class="dot"></span>
      <span class="ip mono">${ip}</span>
      <span class="spacer"></span>
      <button class="run" data-ip="${ip}">Run</button>
      <button class="skip" data-ip="${ip}">Skip</button>
    </div>
    <div class="cred-form" data-ip="${ip}">
      <input type="text" class="username" placeholder="Username (e.g. Administrator)" />
      <input type="password" class="password" placeholder="Password" />
      <button class="confirm" data-ip="${ip}">Confirm &#9656;</button>
      <button class="cancel" data-ip="${ip}">Cancel</button>
    </div>
  `;
  return div;
}

function renderQueue(pending) {
  const list = document.getElementById('queue-list');
  document.getElementById('pending-count').textContent = pending.length;
  if (pending.length === 0) {
    list.innerHTML = '<div class="empty">No devices pending. Waiting on ise_session_watcher.py...</div>';
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
    const badgeClass = 'status-' + (r.status || 'ERROR');
    const detailBits = [];
    if (r.computer) detailBits.push(r.computer);
    if (r.detail) detailBits.push(r.detail);
    if (r.submitted === false) detailBits.push('(not submitted to ISE: ' + (r.submitError || 'unknown error') + ')');
    const needsMac = (r.status === 'ERROR' || r.status === 'NON-COMPLIANT');
    const macBadge = needsMac
      ? `<span class="mac mono">MAC: ${r.mac || 'unknown'}</span>`
      : (r.mac ? `<span class="mac mono">MAC: ${r.mac}</span>` : '');
    const row = document.createElement('div');
    row.className = 'row';
    row.innerHTML = `
      <span class="time">${r.time}</span>
      <span class="ip mono">${r.ip}</span>
      <span class="status-badge ${badgeClass}">${r.status || 'ERROR'}</span>
      ${macBadge}
      <span class="detail">${detailBits.join(' &middot; ')}</span>
    `;
    list.appendChild(row);
  });
}

async function refreshQueue() {
  const data = await fetchJSON('/api/queue');
  currentPending = data.pending;
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
    currentPending = data.pending;
    renderQueue(applyPendingFilter(currentPending));
    refreshResults();
  }

  if (e.target.classList.contains('confirm')) {
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
    currentPending = data.pending;
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
    app.run(host="127.0.0.1", port=UI_PORT, debug=False)