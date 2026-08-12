#!/usr/bin/env python3
"""Receives Ferryman check-ins and emails the Licensor when a deployment goes over.

Deliberately one file, Python standard library only, no dependencies and no database.
It has to run for years without attention, and every dependency is a thing that breaks
while you are not looking. Check-ins are appended to a JSONL file; that is the database.

Run it:

    export FERRYMAN_ALERT_TO=you@example.com
    export FERRYMAN_SMTP_HOST=smtp.example.com
    export FERRYMAN_SMTP_USER=... FERRYMAN_SMTP_PASS=...   # optional
    python3 server.py                                       # listens on :8799

Put it behind a TLS-terminating proxy. It speaks plain HTTP on purpose: doing TLS here
would mean certificate handling in a script that is meant to be auditable at a glance.

Then point installs at it:

    export FERRYMAN_CHECKIN_URL=https://licensing.example.com/checkin
"""

import json
import os
import smtplib
import sys
from datetime import datetime, timezone
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

STORE = Path(os.environ.get("FERRYMAN_STORE", "checkins.jsonl"))
ALERT_TO = os.environ.get("FERRYMAN_ALERT_TO", "").strip()
SMTP_HOST = os.environ.get("FERRYMAN_SMTP_HOST", "").strip()
SMTP_PORT = int(os.environ.get("FERRYMAN_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("FERRYMAN_SMTP_USER", "").strip()
SMTP_PASS = os.environ.get("FERRYMAN_SMTP_PASS", "")
FROM = os.environ.get("FERRYMAN_SMTP_FROM", SMTP_USER or "ferryman@localhost")
PORT = int(os.environ.get("FERRYMAN_PORT", "8799"))
MAX_BODY = 16 * 1024

# Only these keys are stored. Anything else a client sends is dropped rather than
# recorded: PRIVACY.md promises a fixed payload, and the server should not become the
# place that promise quietly stops being true.
ALLOWED = {
    "deployment_id",
    "emails",
    "seats",
    "computers",
    "mobile_devices",
    "over_limit",
    "version",
    "sent_at",
}


def already_alerted(deployment_id: str) -> bool:
    """Whether this deployment has been alerted on before.

    One email per deployment, not one per check-in. Clients check in daily, and an
    alert that arrives every day is an alert that gets filtered into a folder nobody
    opens.
    """
    if not STORE.exists():
        return False
    with STORE.open() as handle:
        for line in handle:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if row.get("deployment_id") == deployment_id and row.get("alerted"):
                return True
    return False


def send_alert(record: dict) -> bool:
    if not (ALERT_TO and SMTP_HOST):
        return False
    message = EmailMessage()
    message["Subject"] = (
        f"Ferryman: deployment over the free tier "
        f"({record.get('seats')} seats, {record.get('computers')} computers)"
    )
    message["From"] = FROM
    message["To"] = ALERT_TO
    message.set_content(
        "A Ferryman deployment reported usage beyond the free tier.\n\n"
        f"  deployment   {record.get('deployment_id')}\n"
        f"  contacts     {', '.join(record.get('emails') or []) or '(none given)'}\n"
        f"  seats        {record.get('seats')}\n"
        f"  computers    {record.get('computers')}\n"
        f"  phones       {record.get('mobile_devices')}\n"
        f"  version      {record.get('version')}\n"
        f"  reported at  {record.get('sent_at')}\n\n"
        "Free tier is 2 seats, 2 computers, 2 phones/tablets. Agents are unlimited.\n"
    )
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as smtp:
            smtp.starttls()
            if SMTP_USER:
                smtp.login(SMTP_USER, SMTP_PASS)
            smtp.send_message(message)
        return True
    except Exception as error:  # noqa: BLE001 - a failed email must not lose the record
        print(f"alert email failed: {error}", file=sys.stderr, flush=True)
        return False


class Handler(BaseHTTPRequestHandler):
    def _reply(self, code: int, body: str = "") -> None:
        payload = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 - name fixed by the stdlib
        if self.path == "/health":
            self._reply(200, '{"ok":true}')
        else:
            self._reply(404, '{"error":"not found"}')

    def do_POST(self) -> None:  # noqa: N802
        if self.path.rstrip("/") not in ("/checkin", ""):
            self._reply(404, '{"error":"not found"}')
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            self._reply(400, '{"error":"bad length"}')
            return
        try:
            payload = json.loads(self.rfile.read(length))
        except ValueError:
            self._reply(400, '{"error":"not json"}')
            return
        if not isinstance(payload, dict) or "deployment_id" not in payload:
            self._reply(400, '{"error":"missing deployment_id"}')
            return

        record = {key: payload[key] for key in ALLOWED if key in payload}
        record["received_at"] = datetime.now(timezone.utc).isoformat()

        alerted = False
        if record.get("over_limit") and not already_alerted(record["deployment_id"]):
            alerted = send_alert(record)
        record["alerted"] = alerted

        # Append before replying: a client that is told "ok" must not be the only place
        # the record exists.
        with STORE.open("a") as handle:
            handle.write(json.dumps(record) + "\n")
        print(
            f"{record['received_at']} {record['deployment_id']} "
            f"seats={record.get('seats')} computers={record.get('computers')} "
            f"over={record.get('over_limit')} alerted={alerted}",
            flush=True,
        )
        self._reply(200, '{"ok":true}')

    def log_message(self, *_args) -> None:
        """Silence the default per-request logging; the handler prints what matters."""


if __name__ == "__main__":
    if not ALERT_TO:
        print("FERRYMAN_ALERT_TO is not set: check-ins are recorded, no email is sent.",
              file=sys.stderr)
    print(f"listening on :{PORT}, appending to {STORE}", flush=True)
    ThreadingHTTPServer(("", PORT), Handler).serve_forever()
