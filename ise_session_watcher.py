"""
ISE Session Watcher — polls Cisco ISE's MnT ActiveList for currently
connected sessions, and tells you about any NEW session that appears
since the last poll (a device that wasn't connected a moment ago).

This closes the "device connects -> we find out" half of the loop.
It does DETECTION ONLY — it does not run the posture check for you.
Per the current plan, you still run posture_agent.ps1 by hand once a
new device shows up here:

    .\\posture_agent.ps1 -ComputerName <ip printed below>

Once that manual step feels solid, this is the natural place to bolt
on automatic triggering later (a subprocess call to the PS1, or a
proper on-device agent) — deliberately not doing that yet, since we
agreed detection-only is the right next step.

Install deps:
    pip install requests --break-system-packages

Run (same env vars as posture_app.py):
    set ISE_HOST=https://10.6.1.90
    set ISE_USER=Dev
    set ISE_PASS=Login@123
    python ise_session_watcher.py
"""

import os
import time
import logging
from xml.etree import ElementTree

import requests
from requests.auth import HTTPBasicAuth

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("ise_session_watcher")

# ---------------------------------------------------------------------------
# Config — same pattern as posture_app.py, nothing hardcoded beyond defaults.
# ---------------------------------------------------------------------------
ISE_HOST = os.environ.get("ISE_HOST", "https://10.6.1.90")
ISE_USER = os.environ.get("ISE_USER", "Dev")
ISE_PASS = os.environ.get("ISE_PASS", "Login@123")
VERIFY_TLS = os.environ.get("ISE_VERIFY_TLS", "false").lower() == "true"
POLL_INTERVAL_SECONDS = int(os.environ.get("WATCHER_POLL_SECONDS", "20"))

# Shared queue file - posture_agent.ps1 reads and dequeues from this file
# when run with no -ComputerName, so each run just grabs "whatever's
# next" instead of you typing an IP each time. Point this at the same
# path from both the watcher and the PS1 (same folder by default).
QUEUE_FILE = os.environ.get("PENDING_QUEUE_FILE", "pending_devices.txt")

AUTH = HTTPBasicAuth(ISE_USER, ISE_PASS)
ACTIVE_LIST_URL = f"{ISE_HOST.rstrip('/')}/admin/API/mnt/Session/ActiveList"


def enqueue(ip: str) -> None:
    """Append one IP to the shared queue file for posture_agent.ps1 to
    pick up. Simple append - PowerShell side removes lines once it has
    claimed them, so this file is always just 'what's still pending'."""
    if not ip or ip == "unknown-ip":
        log.warning("Skipping enqueue - no usable IP for this session.")
        return
    with open(QUEUE_FILE, "a", encoding="utf-8") as f:
        f.write(f"{ip}\n")


def fetch_active_sessions() -> dict:
    """Returns a dict keyed by MAC address -> dict of session fields
    (IP, hostname, etc.), for every session ISE currently reports as
    active. Same generic-field-capture approach as
    get_session_detail() in posture_app.py, since ISE's exact XML tag
    names shift slightly between versions."""
    r = requests.get(ACTIVE_LIST_URL, auth=AUTH, verify=VERIFY_TLS, timeout=15)
    r.raise_for_status()
    if not r.text.strip():
        return {}

    root = ElementTree.fromstring(r.text)
    sessions = {}

    for session_elem in root:
        fields = {}
        for elem in session_elem.iter():
            if len(elem) == 0 and elem.text and elem.text.strip():
                tag = elem.tag.split("}")[-1]  # strip XML namespace if present
                fields[tag] = elem.text.strip()

        mac = (
            fields.get("calling_station_id")
            or fields.get("mac_address")
            or fields.get("MACAddress")
        )
        if mac:
            sessions[mac.upper()] = fields

    return sessions


def describe(fields: dict):
    ip = fields.get("framed_ip_address") or fields.get("ip_address") or "unknown-ip"
    hostname = fields.get("endpoint_id") or fields.get("host_name") or ""
    return ip, hostname


def main():
    log.info(
        "Watching %s every %ss for new sessions... (Ctrl+C to stop)",
        ISE_HOST, POLL_INTERVAL_SECONDS,
    )

    # Prime the baseline on first run. These are logged too (not just
    # counted), so you can see who's already connected — they're still
    # excluded from the "NEW SESSION" alerts below since they were
    # already there before the watcher started.
    seen_macs = set()
    try:
        baseline = fetch_active_sessions()
        seen_macs = set(baseline.keys())
        log.info("Baseline: %d session(s) already active:", len(seen_macs))
        for mac, fields in baseline.items():
            ip, hostname = describe(fields)
            log.info("  ALREADY ACTIVE  MAC=%s  IP=%s  host=%s", mac, ip, hostname or "?")
            enqueue(ip)
    except requests.HTTPError as e:
        log.error("Could not fetch initial session list: %s", e)
    except Exception as e:
        log.error("Unexpected error on initial fetch: %s", e)

    while True:
        time.sleep(POLL_INTERVAL_SECONDS)
        try:
            current = fetch_active_sessions()
        except requests.HTTPError as e:
            log.error("Poll failed: %s", e)
            continue
        except Exception as e:
            log.error("Unexpected error polling ISE: %s", e)
            continue

        new_macs = set(current.keys()) - seen_macs
        for mac in new_macs:
            ip, hostname = describe(current[mac])
            log.info("NEW SESSION  MAC=%s  IP=%s  host=%s", mac, ip, hostname or "?")
            enqueue(ip)

        # Also worth knowing about, though not the focus right now:
        dropped_macs = seen_macs - set(current.keys())
        for mac in dropped_macs:
            log.info("SESSION ENDED  MAC=%s", mac)

        seen_macs = set(current.keys())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Stopped.")
