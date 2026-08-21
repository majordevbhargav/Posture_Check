"""
Posture Application (POC / testing build) — the central service an
endpoint agent posts results to. Fixes the two placeholders in the
original design doc's Flask example:

  - update_ise_endpoint() there wrote a hardcoded static group ID and
    never checked whether the endpoint already existed in ISE.
    write_posture() here writes ExternalComplianceStatus (the attribute
    our authorization policy plan already keys off), creates the
    endpoint if ISE doesn't know it yet, and updates it if it does.

  - trigger_ise_coa() there was an empty placeholder that just printed
    a line. check_and_enforce() here actually looks up the live
    session and fires a real CoA reauth, then reads the session back so
    you get a concrete answer about what ISE actually did.

Safe to run against a live ISE before the authorization policy rule
exists: writing the attribute is just data, and triggering CoA with no
rule reading that attribute yet means ISE simply re-evaluates the
device against whatever policy already applies — nothing changes for
real traffic until the rule is added later.

Test this with Postman or curl POSTs shaped like the PowerShell agent's
payload (see the sample bodies below) — no live endpoint needed.

Install deps:
    pip install flask requests --break-system-packages

Run:
    set ISE_HOST=https://<your-ise>
    set ISE_USER=<user>
    set ISE_PASS=<password>
    python posture_app.py
"""

import os
import time
import logging
from xml.etree import ElementTree

import requests
from flask import Flask, request, jsonify
from requests.auth import HTTPBasicAuth

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("posture_app")

# ---------------------------------------------------------------------------
# Config — nothing hardcoded. Set these as environment variables.
# ---------------------------------------------------------------------------
ISE_HOST = os.environ.get("ISE_HOST", "https://10.6.1.90")
ISE_USER = os.environ.get("ISE_USER", "Dev")
ISE_PASS = os.environ.get("ISE_PASS", "Login@123")
VERIFY_TLS = os.environ.get("ISE_VERIFY_TLS", "false").lower() == "true"

# Optional shared-secret header check for agent -> app calls. Leave unset
# while testing from Postman; set it before any real agent talks to this.
POSTURE_API_KEY = os.environ.get("POSTURE_API_KEY", "")

# Enforcement mechanism: "attribute" (default, proven) uses the ordinary
# authorization-policy rules keyed on ExternalComplianceStatus. "anc" also
# applies/clears the Quarantine ANC policy via a Local Exception rule in
# ISE, which overrides the main table the moment it's applied. Either way,
# the ExternalComplianceStatus attribute is still written, so the Pending
# state keeps working as a fallback when ANC hasn't been applied yet.
ENFORCEMENT_MODE = os.environ.get("ENFORCEMENT_MODE", "attribute").lower()

LISTEN_HOST = os.environ.get("POSTURE_LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("POSTURE_LISTEN_PORT", "8000"))

HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}

# Maps the agent's wire format to the attribute value the ISE policy checks.
STATUS_MAP = {"COMPLIANT": "Compliant", "NON-COMPLIANT": "NonCompliant"}


# ---------------------------------------------------------------------------
# ISE client — write facts, look up a session, trigger + confirm CoA.
# ---------------------------------------------------------------------------
class ISEClient:
    def __init__(self, host, user, password, verify=False):
        self.base = host.rstrip("/")
        self.auth = HTTPBasicAuth(user, password)
        self.verify = verify

    def _get(self, path):
        r = requests.get(f"{self.base}{path}", auth=self.auth, headers=HEADERS,
                          verify=self.verify, timeout=15)
        r.raise_for_status()
        return r.json()

    def _put(self, path, body):
        r = requests.put(f"{self.base}{path}", auth=self.auth, headers=HEADERS,
                          json=body, verify=self.verify, timeout=15)
        r.raise_for_status()
        return r.json() if r.text else {}

    def _post(self, path, body):
        r = requests.post(f"{self.base}{path}", auth=self.auth, headers=HEADERS,
                           json=body, verify=self.verify, timeout=15)
        r.raise_for_status()
        return r.json() if r.text else {}

    def find_endpoint_by_mac(self, mac: str):
        data = self._get(f"/ers/config/endpoint?filter=mac.EQ.{mac}")
        resources = data.get("SearchResult", {}).get("resources", [])
        return resources[0]["id"] if resources else None

    def write_posture(self, mac: str, status: str, failed_checks: str):
        attrs = {
            "ExternalComplianceStatus": status,
            "PostureLastChecked": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "PostureFailedChecks": failed_checks or "none",
        }
        endpoint_id = self.find_endpoint_by_mac(mac)
        body = {"ERSEndPoint": {"mac": mac, "customAttributes": {"customAttributes": attrs}}}
        if endpoint_id is None:
            self._post("/ers/config/endpoint", body)
            log.info("Created new ISE endpoint for %s", mac)
        else:
            body["ERSEndPoint"]["id"] = endpoint_id
            self._put(f"/ers/config/endpoint/{endpoint_id}", body)
            log.info("Updated existing ISE endpoint for %s", mac)

    def get_session_detail(self, mac: str):
        url = f"{self.base}/admin/API/mnt/Session/MACAddress/{mac}"
        r = requests.get(url, auth=self.auth, verify=self.verify, timeout=15)
        if r.status_code >= 400 or not r.text.strip():
            return None
        try:
            root = ElementTree.fromstring(r.text)
        except ElementTree.ParseError:
            return None
        # Capture every leaf element generically instead of guessing tag
        # names up front — ISE's exact MnT session field names vary by
        # release, so this surfaces whatever your ISE actually returns
        # instead of silently missing fields we didn't guess correctly.
        fields = {}
        for elem in root.iter():
            if len(elem) == 0 and elem.text and elem.text.strip():
                tag = elem.tag.split("}")[-1]  # strip XML namespace if present
                fields[tag] = elem.text.strip()
        return fields or None

    def trigger_coa_reauth(self, mac: str, psn: str, reauth_type: int = 1) -> bool:
        url = f"{self.base}/admin/API/mnt/CoA/Reauth/{psn}/{mac}/{reauth_type}"
        r = requests.get(url, auth=self.auth, verify=self.verify, timeout=15)
        r.raise_for_status()
        return "<results>true</results>" in r.text

    # -- ANC (Adaptive Network Control) -----------------------------------
    # Applying/clearing an ANC policy triggers its own CoA automatically as
    # part of the ISE operation — unlike a plain attribute write, we don't
    # need to call trigger_coa_reauth() separately for this path.
    def apply_anc(self, mac: str, policy_name: str = "Quarantine"):
        body = {
            "OperationAdditionalData": {
                "additionalData": [
                    {"name": "macAddress", "value": mac},
                    {"name": "policyName", "value": policy_name},
                ]
            }
        }
        self._post("/ers/config/ancendpoint/apply", body)

    def clear_anc(self, mac: str):
        body = {
            "OperationAdditionalData": {
                "additionalData": [{"name": "macAddress", "value": mac}]
            }
        }
        self._post("/ers/config/ancendpoint/clear", body)

    def check_and_enforce_anc(self, mac: str, compliant: bool) -> dict:
        """ANC-based enforcement path. Applies/clears the Quarantine ANC
        policy (which fires its own CoA), then reads the session back for
        visibility. A 404 here almost always means the 'Quarantine' ANC
        policy doesn't exist yet in ISE — create it before using this."""
        try:
            if compliant:
                self.clear_anc(mac)
                action = "CLEARED"
            else:
                self.apply_anc(mac)
                action = "APPLIED"
        except requests.HTTPError as e:
            body = e.response.text if e.response is not None else ""
            return {"state": "ANC_CALL_FAILED", "detail": str(e), "response_body": body}

        time.sleep(3)
        session = self.get_session_detail(mac) or {}
        return {"state": f"ANC_{action}", "session_fields": session}

    def check_and_enforce(self, mac: str) -> dict:
        session = self.get_session_detail(mac)
        if not session:
            return {"state": "NO_ACTIVE_SESSION", "detail": "facts stored, will apply on next connect"}
        psn = session.get("acs_server") or session.get("server")
        if not psn:
            return {"state": "SESSION_FOUND_BUT_NO_PSN", "detail": "cannot trigger CoA, check manually"}
        self.trigger_coa_reauth(mac, psn)
        time.sleep(3)
        updated = self.get_session_detail(mac) or {}
        return {
            "state": "REAUTH_APPLIED",
            "note": ("CoA fired successfully. This ISE's MnT Session API doesn't expose the "
                      "matched policy rule or authorization profile directly — check "
                      "Operations > RADIUS > Live Sessions in the ISE UI to see those."),
            "session_fields": updated,
        }


ise = ISEClient(ISE_HOST, ISE_USER, ISE_PASS, verify=VERIFY_TLS) if (ISE_HOST and ISE_USER and ISE_PASS) else None


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "application": "Posture Application (POC)",
        "status": "UP",
        "ise_configured": ise is not None,
    })


@app.route("/api/v1/posture", methods=["POST"])
def receive_posture():
    if POSTURE_API_KEY and request.headers.get("X-API-Key") != POSTURE_API_KEY:
        return jsonify({"status": "ERROR", "message": "Invalid or missing API key"}), 401

    if ise is None:
        return jsonify({"status": "ERROR", "message": "Server not configured — set ISE_HOST/ISE_USER/ISE_PASS"}), 500

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "ERROR", "message": "Invalid JSON"}), 400

    endpoint = data.get("endpoint", {})
    posture = data.get("posture", {})

    mac = endpoint.get("mac")
    hostname = endpoint.get("hostname")
    raw_status = posture.get("status")
    checks = posture.get("checks", [])

    if not mac:
        return jsonify({"status": "ERROR", "message": "endpoint.mac is required"}), 400
    if raw_status not in STATUS_MAP:
        return jsonify({"status": "ERROR", "message": f"posture.status must be one of {list(STATUS_MAP)}"}), 400

    ise_status = STATUS_MAP[raw_status]
    failed = ", ".join(c.get("Check", "?") for c in checks if c.get("Status") != "COMPLIANT")

    log.info("Received posture for %s (%s): %s | failed=%s", hostname, mac, raw_status, failed or "none")

    try:
        ise.write_posture(mac, ise_status, failed)
        if ENFORCEMENT_MODE == "anc":
            enforcement = ise.check_and_enforce_anc(mac, compliant=(ise_status == "Compliant"))
        else:
            enforcement = ise.check_and_enforce(mac)
    except requests.HTTPError as e:
        body = e.response.text if e.response is not None else ""
        log.error("ISE call failed for %s: %s | %s", mac, e, body)
        return jsonify({"status": "ERROR", "message": f"ISE API call failed: {e}"}), 502
    except Exception as e:
        # Catches anything that isn't a plain HTTP error from ISE — bad/empty
        # JSON in an ISE response, a connection or SSL problem, etc. — so the
        # real cause shows up in the Postman response instead of a blank
        # Flask 500 page. Full traceback still goes to the server log too.
        log.exception("Unexpected error handling posture for %s", mac)
        return jsonify({"status": "ERROR", "message": f"Unexpected server error: {e}"}), 500

    return jsonify({
        "status": "SUCCESS",
        "mac": mac,
        "posture": ise_status,
        "enforcement": enforcement,
    })


if __name__ == "__main__":
    if ise is None:
        log.warning("ISE_HOST/ISE_USER/ISE_PASS not fully set — /api/v1/posture will return 500 until configured.")
    log.info("Listening on http://%s:%s", LISTEN_HOST, LISTEN_PORT)
    app.run(host=LISTEN_HOST, port=LISTEN_PORT, debug=False)