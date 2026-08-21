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

Two files get created next to this script:
    pending_devices.txt   what's waiting to be checked (drained by
                           posture_agent.ps1 / posture_ui.py)
    seen_macs.txt          every MAC ever queued, so a restart doesn't
                           re-queue devices that were already handled.
                           Delete a MAC's line from this file (or the
                           whole file) to force it to be queued again.
"""

import os
import time
import msvcrt
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

# Persists which MACs have EVER been enqueued, across restarts of this
# script. Without this, restarting the watcher re-treats every currently
# active session as "new" and re-queues everyone all over again — which
# is exactly why pending_devices.txt had the same handful of IPs
# repeated many times over. A MAC is only ever enqueued once; deleting
# this file (or a MAC's line from it) is how you force a re-check.
SEEN_MACS_FILE = os.environ.get("SEEN_MACS_FILE", "seen_macs.txt")

# Simple IP -> MAC lookup, written every time we see a session with a
# usable IP. This exists so posture_ui.py can still show a device's MAC
# on an ERROR result — the compliance check itself may fail before it
# gets far enough to read the MAC directly off the device, but ISE
# already told us the MAC the moment the session appeared, so there's
# no reason for that information to get lost.
IP_MAC_MAP_FILE = os.environ.get("IP_MAC_MAP_FILE", "ip_mac_map.txt")

AUTH = HTTPBasicAuth(ISE_USER, ISE_PASS)
ACTIVE_LIST_URL = f"{ISE_HOST.rstrip('/')}/admin/API/mnt/Session/ActiveList"


def load_seen_macs() -> set:
    if not os.path.exists(SEEN_MACS_FILE):
        return set()
    with open(SEEN_MACS_FILE, "r", encoding="utf-8") as f:
        return {line.strip().upper() for line in f if line.strip()}


def save_seen_macs(seen_macs: set) -> None:
    with open(SEEN_MACS_FILE, "w", encoding="utf-8") as f:
        for mac in sorted(seen_macs):
            f.write(f"{mac}\n")


def record_ip_mac(ip: str, mac: str) -> None:
    """Keeps a simple ip -> MAC lookup file up to date. Rewrites the
    whole file each call — fine at the scale this project runs at."""
    if not ip or ip == "unknown-ip" or not mac:
        return
    mapping = {}
    if os.path.exists(IP_MAC_MAP_FILE):
        with open(IP_MAC_MAP_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if "," in line:
                    k, v = line.strip().split(",", 1)
                    mapping[k] = v
    mapping[ip] = mac
    with open(IP_MAC_MAP_FILE, "w", encoding="utf-8") as f:
        for k, v in mapping.items():
            f.write(f"{k},{v}\n")


def enqueue(ip: str) -> bool:
    """Append one IP to the shared queue file for posture_agent.ps1 to
    pick up. Returns True if the IP is now queued (or already was),
    False if there was nothing usable to queue yet (e.g. no IP assigned
    to the session yet). The caller uses this return value to decide
    whether the owning MAC should be marked 'seen' — a MAC with no IP
    yet must NOT be marked seen, or it'll never get a second chance
    once its IP does show up on a later poll.

    Takes the same advisory lock (byte 0 of the queue file) that
    posture_ui.py uses for its own read-modify-write on this file —
    without it, an append here landing in the middle of the UI's
    read-then-overwrite could get silently discarded."""
    if not ip or ip == "unknown-ip":
        log.warning("Skipping enqueue - no usable IP for this session yet (will retry next poll).")
        return False

    if not os.path.exists(QUEUE_FILE):
        open(QUEUE_FILE, "a", encoding="utf-8").close()

    with open(QUEUE_FILE, "r+", encoding="utf-8") as f:
        msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
        try:
            existing = {line.strip() for line in f.read().splitlines() if line.strip()}
            if ip in existing:
                log.debug("Skipping enqueue - %s is already waiting in the queue.", ip)
                return True
            f.seek(0, os.SEEK_END)
            f.write(f"{ip}\n")
            return True
        finally:
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)


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

    # Loaded from disk, not just this run's memory — this is what
    # prevents a restart from re-queuing devices that were already
    # queued (and possibly already checked) before.
    seen_macs = load_seen_macs()
    log.info("Loaded %d previously-seen MAC(s) from %s", len(seen_macs), SEEN_MACS_FILE)

    try:
        baseline = fetch_active_sessions()
        already_seen = set(baseline.keys()) & seen_macs
        new_in_baseline = set(baseline.keys()) - seen_macs
        log.info(
            "Baseline: %d session(s) active (%d already seen before, %d new)",
            len(baseline), len(already_seen), len(new_in_baseline),
        )
        confirmed = set()
        for mac, fields in baseline.items():
            ip, hostname = describe(fields)
            record_ip_mac(ip, mac)
            if mac in already_seen:
                log.info("  ALREADY SEEN    MAC=%s  IP=%s  host=%s  (not re-queued)", mac, ip, hostname or "?")
                continue
            log.info("  NEW (baseline)  MAC=%s  IP=%s  host=%s", mac, ip, hostname or "?")
            if enqueue(ip):
                confirmed.add(mac)
            # else: no IP yet - deliberately NOT added to seen_macs, so
            # it's picked up again on the next poll once an IP appears.
        seen_macs |= confirmed
        save_seen_macs(seen_macs)
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
        confirmed = set()
        for mac in new_macs:
            ip, hostname = describe(current[mac])
            record_ip_mac(ip, mac)
            log.info("NEW SESSION  MAC=%s  IP=%s  host=%s", mac, ip, hostname or "?")
            if enqueue(ip):
                confirmed.add(mac)
            # else: no IP yet - stays out of seen_macs, retried next poll.

        # Also worth knowing about, though not the focus right now:
        dropped_macs = seen_macs - set(current.keys())
        for mac in dropped_macs:
            log.info("SESSION ENDED  MAC=%s", mac)

        seen_macs |= confirmed
        save_seen_macs(seen_macs)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Stopped.")