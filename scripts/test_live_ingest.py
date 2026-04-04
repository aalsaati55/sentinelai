"""
Quick test: send sample auth.log lines to the live ingest endpoint
and verify it processes them correctly.
"""

import urllib.request
import json

BASE = "http://localhost:8000/api/live"

SAMPLE_AUTH_LINES = [
    "Apr  5 01:50:01 ubuntu sshd[9999]: Failed password for root from 192.168.56.128 port 54321 ssh2",
    "Apr  5 01:50:02 ubuntu sshd[9999]: Failed password for root from 192.168.56.128 port 54322 ssh2",
    "Apr  5 01:50:03 ubuntu sshd[9999]: Failed password for root from 192.168.56.128 port 54323 ssh2",
    "Apr  5 01:50:04 ubuntu sshd[9999]: Failed password for root from 192.168.56.128 port 54324 ssh2",
    "Apr  5 01:50:05 ubuntu sshd[9999]: Failed password for root from 192.168.56.128 port 54325 ssh2",
    "Apr  5 01:50:06 ubuntu sshd[9999]: Accepted password for testuser from 192.168.56.128 port 54326 ssh2",
]

SAMPLE_SYSLOG_LINES = [
    "Apr  5 01:50:10 ubuntu systemd[1]: nginx.service: Failed with result 'exit-code'.",
    "Apr  5 01:50:11 ubuntu systemd[1]: Failed to start A high performance web server.",
]

def post(path, data):
    req = urllib.request.Request(
        f"{BASE}/{path}",
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())

print("Testing /api/live/ingest...")

result = post("ingest", {"source": "auth", "lines": SAMPLE_AUTH_LINES})
print(f"  auth:   {result}")

result = post("ingest", {"source": "syslog", "lines": SAMPLE_SYSLOG_LINES})
print(f"  syslog: {result}")

print("\nDone. Check the dashboard live feed!")
