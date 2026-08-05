import json
import smtplib
import time
import urllib.error
import urllib.request
from datetime import datetime
from email.message import EmailMessage

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Alerter:
    def __init__(self, storage, config):
        self.storage = storage
        self.config = config
        self.min_severity = SEVERITY_ORDER.get(config.get("alerts.min_severity", "medium"), 2)
        self.cooldown = config.get("alerts.cooldown_seconds", 300)
        self.console = config.get("alerts.console", True)
        self.file_path = config.get("alerts.file")
        self.webhook_url = config.get("alerts.webhook_url")
        self.email = config.get("alerts.email", {}) or {}

    def dispatch(self, finding):
        severity = finding.get("severity", "medium")
        if SEVERITY_ORDER.get(severity, 2) < self.min_severity:
            return False
        last = self.storage.last_alert_ts(finding["kind"], finding.get("src_ip"))
        if time.time() - last < self.cooldown:
            return False
        finding.setdefault("ts", time.time())
        alert_id = self.storage.add_alert(finding)
        payload = dict(finding)
        payload["id"] = alert_id
        payload["timestamp"] = datetime.utcfromtimestamp(finding["ts"]).isoformat() + "Z"
        delivered = False
        if self.console:
            delivered = self._to_console(payload) or delivered
        if self.file_path:
            delivered = self._to_file(payload) or delivered
        if self.webhook_url:
            delivered = self._to_webhook(payload) or delivered
        if self.email.get("enabled"):
            delivered = self._to_email(payload) or delivered
        if delivered:
            self.storage.mark_notified(alert_id)
        return delivered

    def _to_console(self, payload):
        print(
            "[%s] %s | %s | %s"
            % (
                payload["timestamp"],
                payload["severity"].upper(),
                payload["title"],
                payload.get("detail", ""),
            ),
            flush=True,
        )
        return True

    def _to_file(self, payload):
        try:
            with open(self.file_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload) + "\n")
            return True
        except OSError:
            return False

    def _to_webhook(self, payload):
        body = json.dumps(
            {
                "text": "%s [%s] %s" % (payload["severity"].upper(), payload["kind"], payload["title"]),
                "alert": payload,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            self.webhook_url, data=body, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return 200 <= response.status < 300
        except (urllib.error.URLError, OSError):
            return False

    def _to_email(self, payload):
        message = EmailMessage()
        message["Subject"] = "[netmon][%s] %s" % (payload["severity"].upper(), payload["title"])
        message["From"] = self.email.get("sender")
        message["To"] = ", ".join(self.email.get("recipients", []))
        message.set_content(json.dumps(payload, indent=2))
        try:
            with smtplib.SMTP(self.email.get("smtp_host"), self.email.get("smtp_port", 587), timeout=15) as server:
                server.starttls()
                if self.email.get("username"):
                    server.login(self.email["username"], self.email.get("password", ""))
                server.send_message(message)
            return True
        except Exception:
            return False
