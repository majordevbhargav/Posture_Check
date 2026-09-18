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
import urllib.request
import urllib.parse
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

# RESULTS/NEEDS_ATTENTION are written here after every change and reloaded
# at startup, so a Flask restart doesn't wipe your history. Best-effort:
# a write failure here never blocks or fails a live check.
STATE_FILE = os.environ.get("POSTURE_UI_STATE_FILE", "posture_ui_state.json")
DB_FILE = os.environ.get("POSTURE_DB_FILE", "posture.db")

import sqlite3

app = Flask(__name__)

DASHBOARD_HTML_PATH = Path(__file__).parent / "dashboard.html"


def _read_dashboard_html() -> str:
    try:
        return DASHBOARD_HTML_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ("<h1>dashboard.html not found</h1><p>Expected it next to posture_ui.py. "
                "The original console is still available at <a href='/console'>/console</a>.</p>")


# SQLite Database Helper Functions
def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS endpoints (
            mac TEXT PRIMARY KEY,
            ip TEXT,
            hostname TEXT,
            os TEXT,
            os_version TEXT,
            last_seen TEXT,
            first_seen TEXT,
            apps_count INTEGER DEFAULT 0
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT,
            ip TEXT,
            timestamp TEXT,
            status TEXT,
            detail TEXT,
            submitted INTEGER DEFAULT 0,
            submit_error TEXT,
            apps_count INTEGER DEFAULT 0
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS check_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER REFERENCES assessments(id) ON DELETE CASCADE,
            check_name TEXT,
            status TEXT,
            detail TEXT
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS needs_attention (
            ip TEXT PRIMARY KEY,
            added_at TEXT
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS endpoint_ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT,
            port INTEGER,
            process TEXT,
            pid INTEGER,
            timestamp TEXT
        );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_assessments_mac ON assessments(mac);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_check_results_assessment ON check_results(assessment_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_endpoint_ports_mac ON endpoint_ports(mac);")
        conn.commit()


def migrate_json_to_db():
    json_path = Path(STATE_FILE)
    if not json_path.exists():
        return
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"Error reading JSON state file for migration: {e}")
        return

    print("Migrating JSON state to SQLite database...")
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM assessments")
        if cursor.fetchone()[0] > 0:
            print("Database already has records, skipping migration.")
            return

        for r in data.get("results", []):
            date_val = r.get("date") or "2026-08-24"
            time_val = r.get("time") or "00:00:00"
            timestamp = f"{date_val}T{time_val}Z"
            mac = (r.get("mac") or r.get("ip") or "unknown").upper()
            ip = r.get("ip")
            hostname = r.get("computer")
            os_name = r.get("os")
            status = r.get("status")
            detail = r.get("detail")
            submitted = 1 if r.get("submitted") else 0
            submit_error = r.get("submitError")

            cursor.execute("""
                INSERT INTO endpoints (mac, ip, hostname, os, last_seen, first_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                    ip = excluded.ip,
                    hostname = excluded.hostname,
                    os = COALESCE(excluded.os, endpoints.os),
                    last_seen = excluded.last_seen
            """, (mac, ip, hostname, os_name, timestamp, timestamp))

            cursor.execute("""
                INSERT INTO assessments (mac, ip, timestamp, status, detail, submitted, submit_error)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (mac, ip, timestamp, status, detail, submitted, submit_error))
            assessment_id = cursor.lastrowid

            cursor.execute("""
                INSERT INTO check_results (assessment_id, check_name, status, detail)
                VALUES (?, ?, ?, ?)
            """, (assessment_id, "Windows Firewall", status, detail))

        for ip in data.get("needs_attention", []):
            cursor.execute("""
                INSERT OR IGNORE INTO needs_attention (ip, added_at)
                VALUES (?, ?)
            """, (ip, datetime.datetime.now().isoformat()))

        conn.commit()
    print("Migration complete. Renaming JSON state file to avoid future migrations.")
    try:
        json_path.rename(json_path.with_suffix(".json.bak"))
    except Exception as e:
        print(f"Error renaming JSON state file: {e}")


def lookup_known_mac(ip: str):
    """Best-effort MAC lookup from the watcher's ip->mac map. Returns
    None if the file doesn't exist or has no entry for this IP."""
    # First check database for known endpoints
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT mac FROM endpoints WHERE ip = ? LIMIT 1", (ip,))
            row = cursor.fetchone()
            if row:
                return row["mac"]
    except Exception:
        pass
        
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


def load_state() -> None:
    """Called once at startup - restores RESULTS/NEEDS_ATTENTION from the
    last run, if the state file exists and is readable."""
    init_db()
    migrate_json_to_db()


def add_needs_attention(ip: str):
    with get_db() as conn:
        conn.execute("""
            INSERT OR IGNORE INTO needs_attention (ip, added_at)
            VALUES (?, ?)
        """, (ip, datetime.datetime.now().isoformat()))
        conn.commit()
    return get_needs_attention()


def remove_needs_attention(ip: str):
    with get_db() as conn:
        conn.execute("DELETE FROM needs_attention WHERE ip = ?", (ip,))
        conn.commit()
    return get_needs_attention()


def get_needs_attention():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ip FROM needs_attention")
        return [row[0] for row in cursor.fetchall()]


def append_result(entry: dict):
    # entry keys: time, date, ip, computer, mac, os, status, detail, submitted, submitError, checks, appsCount, listening_ports
    date_val = entry.get("date") or datetime.datetime.now().strftime("%Y-%m-%d")
    time_val = entry.get("time") or datetime.datetime.now().strftime("%H:%M:%S")
    timestamp = f"{date_val}T{time_val}Z"
    
    mac = (entry.get("mac") or entry.get("ip") or "unknown").upper()
    ip = entry.get("ip")
    hostname = entry.get("computer")
    os_name = entry.get("os")
    os_version = entry.get("osVersion")
    status = entry.get("status")
    detail = entry.get("detail")
    submitted = 1 if entry.get("submitted") else 0
    submit_error = entry.get("submitError")
    apps_count = entry.get("appsCount") or 0
    checks = entry.get("checks") or []
    ports = entry.get("listening_ports") or []
    
    with get_db() as conn:
        cursor = conn.cursor()
        
        # 1. Update/Insert endpoint
        cursor.execute("""
            INSERT INTO endpoints (mac, ip, hostname, os, os_version, last_seen, first_seen, apps_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                ip = excluded.ip,
                hostname = excluded.hostname,
                os = COALESCE(excluded.os, endpoints.os),
                os_version = COALESCE(excluded.os_version, endpoints.os_version),
                last_seen = excluded.last_seen,
                apps_count = excluded.apps_count
        """, (mac, ip, hostname, os_name, os_version, timestamp, timestamp, apps_count))
        
        # 2. Insert assessment
        cursor.execute("""
            INSERT INTO assessments (mac, ip, timestamp, status, detail, submitted, submit_error, apps_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (mac, ip, timestamp, status, detail, submitted, submit_error, apps_count))
        assessment_id = cursor.lastrowid
        
        # 3. Insert checks
        if checks:
            for c in checks:
                cursor.execute("""
                    INSERT INTO check_results (assessment_id, check_name, status, detail)
                    VALUES (?, ?, ?, ?)
                """, (assessment_id, c.get("Check"), c.get("Status"), c.get("Details")))
        else:
            cursor.execute("""
                INSERT INTO check_results (assessment_id, check_name, status, detail)
                VALUES (?, ?, ?, ?)
            """, (assessment_id, "Windows Firewall", status, detail))
            
        # 4. Save ports if any
        if ports:
            # Clear old ports for this endpoint to keep it updated with current state
            cursor.execute("DELETE FROM endpoint_ports WHERE mac = ?", (mac,))
            for p in ports:
                cursor.execute("""
                    INSERT INTO endpoint_ports (mac, port, process, pid, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, (mac, p.get("port"), p.get("process"), p.get("pid"), timestamp))
                
        conn.commit()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def dashboard_page():
    return Response(_read_dashboard_html(), mimetype="text/html")


@app.route("/console")
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
        entry = {"time": datetime.datetime.now().strftime("%H:%M:%S"),
                  "date": datetime.datetime.now().strftime("%Y-%m-%d"), "ip": ip,
                  "mac": lookup_known_mac(ip), "status": "ERROR",
                  "detail": "Timed out waiting for the check to finish."}
        append_result(entry)
        return entry
    except Exception as e:
        # PowerShell itself not runnable, permissions error, etc.
        add_needs_attention(ip)
        entry = {"time": datetime.datetime.now().strftime("%H:%M:%S"),
                  "date": datetime.datetime.now().strftime("%Y-%m-%d"), "ip": ip,
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
        entry = {"time": datetime.datetime.now().strftime("%H:%M:%S"),
                  "date": datetime.datetime.now().strftime("%Y-%m-%d"), "ip": ip,
                  "mac": lookup_known_mac(ip), "status": "ERROR", "detail": detail}
    else:
        is_error = parsed.get("status") == "ERROR"
        if is_error:
            add_needs_attention(ip)
        entry = {
            "time": datetime.datetime.now().strftime("%H:%M:%S"),
            "date": datetime.datetime.now().strftime("%Y-%m-%d"),
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
    limit = request.args.get("limit", default=50, type=int)
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, mac, ip, timestamp, status, detail, submitted, submit_error, apps_count
            FROM assessments
            ORDER BY timestamp DESC, id DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        
        results = []
        for row in rows:
            ts_str = row["timestamp"]
            if "T" in ts_str:
                date_part, time_part = ts_str.rstrip("Z").split("T")
            else:
                date_part = ts_str.split()[0] if ts_str else ""
                time_part = ts_str.split()[1] if ts_str and len(ts_str.split()) > 1 else ""
                
            cursor.execute("""
                SELECT check_name, status, detail
                FROM check_results
                WHERE assessment_id = ?
            """, (row["id"],))
            checks_rows = cursor.fetchall()
            checks = [{"Check": r["check_name"], "Status": r["status"], "Details": r["detail"]} for r in checks_rows]
            
            cursor.execute("SELECT hostname, os, os_version FROM endpoints WHERE mac = ?", (row["mac"],))
            ep_row = cursor.fetchone()
            hostname = ep_row["hostname"] if ep_row else row["ip"]
            os_name = ep_row["os"] if ep_row else None
            os_version = ep_row["os_version"] if ep_row else None
            
            results.append({
                "time": time_part,
                "date": date_part,
                "ip": row["ip"],
                "computer": hostname,
                "mac": row["mac"],
                "os": os_name,
                "osVersion": os_version,
                "status": row["status"],
                "detail": row["detail"],
                "submitted": bool(row["submitted"]),
                "submitError": row["submit_error"],
                "appsCount": row["apps_count"],
                "checks": checks
            })
        return jsonify({"results": results})


@app.route("/api/skip", methods=["POST"])
def api_skip():
    data = request.get_json(force=True)
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "ip is required"}), 400
    
    # Get MAC for the IP
    mac = lookup_known_mac(ip) or ip.upper()
    remaining = remove_needs_attention(ip)
    
    append_result({
        "time": datetime.datetime.now().strftime("%H:%M:%S"),
        "date": datetime.datetime.now().strftime("%Y-%m-%d"),
        "ip": ip,
        "mac": mac,
        "status": "SKIPPED",
        "detail": "Skipped - not checked.",
        "submitted": False,
        "submitError": None
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

    remove_needs_attention(ip)
    run_check(ip, username or None, password or None)
    return jsonify({"needs_attention": get_needs_attention()})


def get_category_percent(check_name: str) -> float:
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                WITH latest_assessments AS (
                    SELECT mac, MAX(timestamp) as max_ts
                    FROM assessments
                    GROUP BY mac
                ),
                latest_ids AS (
                    SELECT a.id
                    FROM assessments a
                    JOIN latest_assessments la ON a.mac = la.mac AND a.timestamp = la.max_ts
                )
                SELECT cr.status, COUNT(*) as cnt
                FROM check_results cr
                JOIN latest_ids li ON cr.assessment_id = li.id
                WHERE cr.check_name = ? OR cr.check_name = ?
                GROUP BY cr.status
            """, (check_name, "Windows Firewall" if check_name == "Firewall" else check_name))
            
            rows = cursor.fetchall()
            compliant = 0
            total = 0
            for r in rows:
                total += r["cnt"]
                if r["status"] == "COMPLIANT":
                    compliant += r["cnt"]
            return round((compliant / total) * 100) if total else None
    except Exception as e:
        print(f"Error calculating percent for {check_name}: {e}")
        return None


OTHER_CATEGORIES = ["OS Patch Level", "Disk Encryption", "Security Settings", "Application Control"]


@app.route("/api/dashboard/summary")
def api_dashboard_summary():
    needs = get_needs_attention()
    needs_set = set(needs)
    at_risk = len(needs)
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            WITH latest_assessments AS (
                SELECT mac, MAX(timestamp) as max_ts
                FROM assessments
                GROUP BY mac
            )
            SELECT a.mac, a.status, a.ip
            FROM assessments a
            JOIN latest_assessments la ON a.mac = la.mac AND a.timestamp = la.max_ts
        """)
        rows = cursor.fetchall()
        
        latest_endpoints = {}
        for r in rows:
            latest_endpoints[r["mac"]] = (r["status"], r["ip"])
            
        cursor.execute("SELECT mac, ip FROM endpoints")
        for r in cursor.fetchall():
            if r["mac"] not in latest_endpoints:
                latest_endpoints[r["mac"]] = ("Never Checked", r["ip"])
                
        compliant = 0
        non_compliant = 0
        for mac, (status, ip) in latest_endpoints.items():
            if ip in needs_set or mac in needs_set:
                continue
            if status == "COMPLIANT":
                compliant += 1
            elif status == "NON-COMPLIANT":
                non_compliant += 1
                
        total = len(latest_endpoints)
        
        today = datetime.datetime.now().strftime("%Y-%m-%d")
        cursor.execute("SELECT COUNT(*) FROM assessments WHERE timestamp LIKE ?", (f"{today}%",))
        assessments_today = cursor.fetchone()[0]
        
    score = round((compliant * 1.0 + at_risk * 0.5) / total * 100) if total else None
    
    return jsonify({
        "total_endpoints": total,
        "compliant": compliant,
        "non_compliant": non_compliant,
        "at_risk": at_risk,
        "assessments_today": assessments_today,
        "compliance_score": score,
    })


@app.route("/api/dashboard/trend")
def api_dashboard_trend():
    days_param = request.args.get("days", type=int) or 7
    days_param = max(1, min(days_param, 90))
    
    with get_db() as conn:
        cursor = conn.cursor()
        
        if days_param == 1:
            now = datetime.datetime.now()
            current_hour = now.replace(minute=0, second=0, microsecond=0)
            hour_starts = [current_hour - datetime.timedelta(hours=i) for i in range(23, -1, -1)]
            keys = [h.strftime("%Y-%m-%d %H") for h in hour_starts]
            labels = [h.strftime("%H:00") for h in hour_starts]
            buckets = {k: {"compliant": 0, "non_compliant": 0, "at_risk": 0} for k in keys}
            cutoff = hour_starts[0].strftime("%Y-%m-%dT%H:%M:%SZ")
            
            cursor.execute("""
                SELECT timestamp, status
                FROM assessments
                WHERE timestamp >= ?
            """, (cutoff,))
            rows = cursor.fetchall()
            
            for row in rows:
                ts_str = row["timestamp"]
                try:
                    if "T" in ts_str:
                        ts = datetime.datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ")
                    else:
                        ts = datetime.datetime.strptime(ts_str.split(".")[0], "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    continue
                
                bucket_key = ts.strftime("%Y-%m-%d %H")
                if bucket_key in buckets:
                    b = buckets[bucket_key]
                    status = row["status"]
                    if status == "COMPLIANT":
                        b["compliant"] += 1
                    elif status == "NON-COMPLIANT":
                        b["non_compliant"] += 1
                    elif status == "ERROR":
                        b["at_risk"] += 1
                        
            return jsonify({"days": labels, "buckets": [buckets[k] for k in keys], "granularity": "hourly"})
            
        today = datetime.date.today()
        days = [(today - datetime.timedelta(days=i)).strftime("%Y-%m-%d") for i in range(days_param - 1, -1, -1)]
        buckets = {d: {"compliant": 0, "non_compliant": 0, "at_risk": 0} for d in days}
        cutoff = days[0] + "T00:00:00Z"
        
        cursor.execute("""
            SELECT timestamp, status
            FROM assessments
            WHERE timestamp >= ?
        """, (cutoff,))
        rows = cursor.fetchall()
        
        for row in rows:
            ts_str = row["timestamp"]
            date_key = ts_str.split("T")[0] if "T" in ts_str else ts_str.split()[0]
            if date_key in buckets:
                b = buckets[date_key]
                status = row["status"]
                if status == "COMPLIANT":
                    b["compliant"] += 1
                elif status == "NON-COMPLIANT":
                    b["non_compliant"] += 1
                elif status == "ERROR":
                    b["at_risk"] += 1
                    
        return jsonify({"days": days, "buckets": [buckets[d] for d in days], "granularity": "daily"})


@app.route("/api/dashboard/categories")
def api_dashboard_categories():
    firewall_pct = get_category_percent("Firewall")
    av_pct = get_category_percent("Anti-Virus")
    ports_pct = get_category_percent("Open Ports")
    
    categories = [
        {"name": "Firewall", "implemented": True, "percent": firewall_pct},
        {"name": "Anti-Virus", "implemented": False, "percent": av_pct},
        {"name": "Open Ports", "implemented": True, "percent": ports_pct}
    ]
    categories += [{"name": n, "implemented": False, "percent": None} for n in OTHER_CATEGORIES]
    return jsonify({"categories": categories})


@app.route("/api/dashboard/endpoints")
def api_dashboard_endpoints():
    needs = set(get_needs_attention())
    
    known_ips = {}
    p = Path(IP_MAC_MAP_FILE)
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            if "," in line:
                ip, mac = line.split(",", 1)
                known_ips[ip.strip()] = mac.strip()
                
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT mac, ip, hostname, os, os_version, last_seen, apps_count FROM endpoints")
        ep_rows = cursor.fetchall()
        
        rows = []
        seen_keys = set()
        for ep in ep_rows:
            mac = ep["mac"]
            ip = ep["ip"]
            hostname = ep["hostname"]
            os_name = ep["os"]
            os_version = ep["os_version"]
            last_seen = ep["last_seen"]
            apps_count = ep["apps_count"]
            seen_keys.add(mac)
            
            cursor.execute("""
                SELECT id, status, detail, timestamp
                FROM assessments
                WHERE mac = ?
                ORDER BY timestamp DESC, id DESC
                LIMIT 1
            """, (mac,))
            a_row = cursor.fetchone()
            
            status = "Never Checked"
            checks = []
            if a_row:
                if ip in needs or mac in needs:
                    status = "At Risk"
                else:
                    status = (a_row["status"] or "Unknown").title()
                
                cursor.execute("""
                    SELECT check_name, status, detail
                    FROM check_results
                    WHERE assessment_id = ?
                """, (a_row["id"],))
                checks_rows = cursor.fetchall()
                checks = [{"name": r["check_name"], "status": r["status"], "detail": r["detail"]} for r in checks_rows]
                
            last_seen_date = None
            last_seen_time = None
            if last_seen:
                if "T" in last_seen:
                    last_seen_date, last_seen_time = last_seen.rstrip("Z").split("T")
                else:
                    parts = last_seen.split()
                    last_seen_date = parts[0]
                    last_seen_time = parts[1] if len(parts) > 1 else ""
                    
            cursor.execute("""
                SELECT port, process, pid
                FROM endpoint_ports
                WHERE mac = ?
                ORDER BY port ASC
            """, (mac,))
            ports_rows = cursor.fetchall()
            ports = [{"port": r["port"], "process": r["process"], "pid": r["pid"]} for r in ports_rows]
            
            rows.append({
                "identity": mac,
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "os": os_name,
                "os_version": os_version,
                "status": status,
                "last_seen": last_seen_time,
                "last_seen_date": last_seen_date,
                "apps_count": apps_count,
                "checks": checks,
                "ports": ports
            })
            
        for ip, mac in known_ips.items():
            key = (mac or ip).upper()
            if key in seen_keys:
                continue
            seen_keys.add(key)
            status = "At Risk" if ip in needs or key in needs else "Never Checked"
            rows.append({
                "identity": key, "ip": ip, "mac": mac, "hostname": None,
                "os": None, "os_version": None, "status": status,
                "last_seen": None, "last_seen_date": None,
                "apps_count": 0, "checks": [], "ports": []
            })
            
    rows.sort(key=lambda r: (r.get("last_seen_date") or "", r.get("last_seen") or ""), reverse=True)
    return jsonify({"endpoints": rows})


@app.route("/api/dashboard/health")
def api_dashboard_health():
    parts = urllib.parse.urlsplit(POSTURE_SERVER)
    health_url = f"{parts.scheme}://{parts.netloc}/health"
    posture_app_ok = False
    ise_configured = None
    try:
        with urllib.request.urlopen(health_url, timeout=3) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            posture_app_ok = True
            ise_configured = body.get("ise_configured")
    except Exception:
        pass

    watcher_last_seen = None
    watcher_recent = False
    map_path = Path(IP_MAC_MAP_FILE)
    if map_path.exists():
        age = time.time() - map_path.stat().st_mtime
        watcher_last_seen = f"{int(age)}s ago" if age < 120 else f"{int(age // 60)}m ago"
        watcher_recent = age < 300

    return jsonify({
        "posture_app": {"reachable": posture_app_ok, "url": health_url},
        "ise_configured": ise_configured,
        "watcher": {"last_activity": watcher_last_seen, "recent": watcher_recent},
        "database": {"built": True, "note": "SQLite database active.", "path": DB_FILE},
        "policy_service": {"built": False},
        "report_service": {"built": False},
        "notification_service": {"built": False},
    })


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
    load_state()
    print(f"Restored {len(RESULTS)} result(s) and {len(NEEDS_ATTENTION)} needs-attention item(s) from {STATE_FILE}")
    print("Auto-worker running: new devices are checked automatically in the background.")
    threading.Thread(target=auto_worker, daemon=True).start()
    app.run(host="127.0.0.1", port=UI_PORT, debug=False, threaded=True)