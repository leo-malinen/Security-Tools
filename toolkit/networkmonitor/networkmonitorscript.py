#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import random
import re
import signal
import smtplib
import socket
import sqlite3
import statistics
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage

__version__ = "2.0.0"

HERE = os.path.dirname(os.path.abspath(__file__))

DEFAULT_CONFIG = {
    "database": os.path.join(HERE, "netmon.db"),
    "capture": {
        "interface": "any",
        "log_file": "/var/log/auth.log",
        "poll_interval": 2,
    },
    "detection": {
        "port_scan": {"window_seconds": 60, "distinct_ports": 15},
        "brute_force": {
            "window_seconds": 300,
            "failed_logins": 8,
            "ports": [22, 23, 3389, 21, 3306, 5432],
        },
        "traffic_spike": {
            "window_seconds": 60,
            "baseline_windows": 10,
            "stddev_multiplier": 3.0,
            "min_events": 50,
        },
        "suspicious_ip": {"score_threshold": 50},
    },
    "scoring": {
        "port_scan": 40,
        "brute_force": 50,
        "traffic_spike": 20,
        "blocklist_hit": 60,
        "decay_hours": 24,
    },
    "whitelist": ["127.0.0.1", "10.0.0.1"],
    "alerts": {
        "console": True,
        "file": os.path.join(HERE, "alerts.log"),
        "webhook_url": "",
        "email": {
            "enabled": False,
            "smtp_host": "smtp.example.com",
            "smtp_port": 587,
            "username": "alerts@example.com",
            "password": "changeme",
            "sender": "alerts@example.com",
            "recipients": ["soc@example.com"],
        },
        "min_severity": "medium",
        "cooldown_seconds": 300,
    },
    "threat_feeds": {
        "refresh_hours": 6,
        "timeout": 30,
        "user_agent": "netmon-threatfeed/%s" % __version__,
        "sources": [
            "https://lists.blocklist.de/lists/ssh.txt",
            "https://www.spamhaus.org/drop/drop.txt",
        ],
    },
}

CONFIG_CANDIDATES = ("config.yaml", "config.yml", "config.json")


def _deep_merge(base, override):
    result = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


class Config:
    def __init__(self, data=None, source=None):
        self._data = _deep_merge(DEFAULT_CONFIG, data or {})
        self.source = source

    def get(self, path, default=None):
        node = self._data
        for part in path.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node if node is not None else default

    @property
    def raw(self):
        return self._data


def _read_config_file(path):
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    if path.lower().endswith(".json"):
        return json.loads(text)
    try:
        import yaml  # optional dependency
    except ImportError:
        try:
            return json.loads(text)
        except ValueError:
            print(
                "warning: %s needs PyYAML (pip install PyYAML); using defaults" % path,
                file=sys.stderr,
            )
            return {}
    return yaml.safe_load(text) or {}


def load_config(path=None):
    target = path or os.environ.get("NETMON_CONFIG")
    if not target:
        for name in CONFIG_CANDIDATES:
            candidate = os.path.join(HERE, name)
            if os.path.exists(candidate):
                target = candidate
                break
    if not target:
        return Config()
    if not os.path.exists(target):
        raise SystemExit("config file not found: %s" % target)
    return Config(_read_config_file(target), source=target)

SCHEMA = """
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    length INTEGER,
    flags TEXT
);
CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(ts);
CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src_ip, ts);

CREATE TABLE IF NOT EXISTS auth_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    src_ip TEXT NOT NULL,
    username TEXT,
    service TEXT,
    port INTEGER,
    success INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_auth_ts ON auth_events(ts);
CREATE INDEX IF NOT EXISTS idx_auth_src ON auth_events(src_ip, ts);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    src_ip TEXT,
    title TEXT NOT NULL,
    detail TEXT,
    score INTEGER DEFAULT 0,
    notified INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_kind ON alerts(kind, ts);

CREATE TABLE IF NOT EXISTS ip_reputation (
    ip TEXT PRIMARY KEY,
    score INTEGER NOT NULL DEFAULT 0,
    first_seen REAL,
    last_seen REAL,
    blocklisted INTEGER NOT NULL DEFAULT 0,
    sources TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS blocklist (
    ip TEXT PRIMARY KEY,
    source TEXT,
    fetched_at REAL
);

CREATE TABLE IF NOT EXISTS traffic_windows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    window_start REAL NOT NULL,
    window_end REAL NOT NULL,
    packet_count INTEGER NOT NULL,
    byte_count INTEGER NOT NULL,
    unique_sources INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_windows_start ON traffic_windows(window_start);

CREATE TABLE IF NOT EXISTS state (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


class Storage:
    def __init__(self, path):
        self.path = path
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def close(self):
        with self._lock:
            self._conn.close()

    def execute(self, sql, params=()):
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def executemany(self, sql, rows):
        with self._lock:
            cur = self._conn.executemany(sql, rows)
            self._conn.commit()
            return cur

    def query(self, sql, params=()):
        with self._lock:
            return [dict(row) for row in self._conn.execute(sql, params).fetchall()]

    def one(self, sql, params=()):
        rows = self.query(sql, params)
        return rows[0] if rows else None

    # -- writers ------------------------------------------------------------

    def add_packets(self, packets):
        rows = [
            (
                p.get("ts", time.time()),
                p.get("src_ip"),
                p.get("dst_ip"),
                p.get("src_port"),
                p.get("dst_port"),
                p.get("protocol"),
                p.get("length", 0),
                p.get("flags"),
            )
            for p in packets
        ]
        if rows:
            self.executemany(
                "INSERT INTO packets (ts, src_ip, dst_ip, src_port, dst_port, protocol, length, flags)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
        return len(rows)

    def add_packet(self, packet):
        self.add_packets([packet])

    def add_auth_event(self, event):
        self.execute(
            "INSERT INTO auth_events (ts, src_ip, username, service, port, success)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                event.get("ts", time.time()),
                event.get("src_ip"),
                event.get("username"),
                event.get("service"),
                event.get("port"),
                1 if event.get("success") else 0,
            ),
        )

    def add_auth_events(self, events):
        rows = [
            (
                e.get("ts", time.time()),
                e.get("src_ip"),
                e.get("username"),
                e.get("service"),
                e.get("port"),
                1 if e.get("success") else 0,
            )
            for e in events
        ]
        if rows:
            self.executemany(
                "INSERT INTO auth_events (ts, src_ip, username, service, port, success)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                rows,
            )
        return len(rows)

    def add_alert(self, alert):
        cur = self.execute(
            "INSERT INTO alerts (ts, kind, severity, src_ip, title, detail, score, notified)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
            (
                alert.get("ts", time.time()),
                alert["kind"],
                alert.get("severity", "medium"),
                alert.get("src_ip"),
                alert["title"],
                alert.get("detail", ""),
                alert.get("score", 0),
            ),
        )
        return cur.lastrowid

    def mark_notified(self, alert_id):
        self.execute("UPDATE alerts SET notified = 1 WHERE id = ?", (alert_id,))

    def last_alert_ts(self, kind, src_ip):
        row = self.one(
            "SELECT MAX(ts) AS ts FROM alerts WHERE kind = ? AND src_ip IS ?",
            (kind, src_ip),
        )
        return row["ts"] if row and row["ts"] else 0.0

    def bump_reputation(self, ip, points, note=None, blocklisted=None):
        now = time.time()
        existing = self.one("SELECT * FROM ip_reputation WHERE ip = ?", (ip,))
        if existing is None:
            self.execute(
                "INSERT INTO ip_reputation (ip, score, first_seen, last_seen, blocklisted, notes)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (ip, min(100, points), now, now, 1 if blocklisted else 0, note or ""),
            )
            return min(100, points)
        score = min(100, int(existing["score"]) + points)
        flag = existing["blocklisted"] if blocklisted is None else (1 if blocklisted else 0)
        notes = existing["notes"] or ""
        if note and note not in notes:
            notes = (notes + "; " + note).strip("; ")
        self.execute(
            "UPDATE ip_reputation SET score = ?, last_seen = ?, blocklisted = ?, notes = ? WHERE ip = ?",
            (score, now, flag, notes, ip),
        )
        return score

    def decay_reputation(self, hours, amount=5):
        cutoff = time.time() - hours * 3600
        self.execute(
            "UPDATE ip_reputation SET score = MAX(0, score - ?) WHERE last_seen < ?",
            (amount, cutoff),
        )

    def replace_blocklist(self, entries):
        now = time.time()
        rows = [(ip, source, now) for ip, source in entries]
        if not rows:
            return 0
        self.executemany(
            "INSERT INTO blocklist (ip, source, fetched_at) VALUES (?, ?, ?)"
            " ON CONFLICT(ip) DO UPDATE SET source = excluded.source, fetched_at = excluded.fetched_at",
            rows,
        )
        return len(rows)

    def is_blocklisted(self, ip):
        return self.one("SELECT ip FROM blocklist WHERE ip = ?", (ip,)) is not None

    def set_state(self, key, value):
        self.execute(
            "INSERT INTO state (key, value) VALUES (?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, str(value)),
        )

    def get_state(self, key, default=None):
        row = self.one("SELECT value FROM state WHERE key = ?", (key,))
        return row["value"] if row else default

    def purge(self, days=7):
        cutoff = time.time() - days * 86400
        self.execute("DELETE FROM packets WHERE ts < ?", (cutoff,))
        self.execute("DELETE FROM auth_events WHERE ts < ?", (cutoff,))
        self.execute("DELETE FROM traffic_windows WHERE window_start < ?", (cutoff,))


# ---------------------------------------------------------------------------
# Alerting
# ---------------------------------------------------------------------------

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
        payload["timestamp"] = (
            datetime.fromtimestamp(finding["ts"], tz=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
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
            "[%s] %-8s %s | %s"
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
                "text": "%s [%s] %s"
                % (payload["severity"].upper(), payload["kind"], payload["title"]),
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
            with smtplib.SMTP(
                self.email.get("smtp_host"), self.email.get("smtp_port", 587), timeout=15
            ) as server:
                server.starttls()
                if self.email.get("username"):
                    server.login(self.email["username"], self.email.get("password", ""))
                server.send_message(message)
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


class DetectionEngine:
    def __init__(self, storage, config, alerter):
        self.storage = storage
        self.config = config
        self.alerter = alerter
        self.whitelist = set(config.get("whitelist", []) or [])
        self.scoring = config.get("scoring", {}) or {}

    def run_cycle(self):
        findings = []
        findings.extend(self.detect_port_scans())
        findings.extend(self.detect_brute_force())
        findings.extend(self.detect_traffic_spikes())
        findings.extend(self.detect_suspicious_ips())
        self.storage.decay_reputation(self.scoring.get("decay_hours", 24))
        return findings

    def _skip(self, ip):
        return ip is None or ip in self.whitelist

    def detect_port_scans(self):
        window = self.config.get("detection.port_scan.window_seconds", 60)
        threshold = self.config.get("detection.port_scan.distinct_ports", 15)
        since = time.time() - window
        rows = self.storage.query(
            "SELECT src_ip, COUNT(DISTINCT dst_port) AS ports, COUNT(*) AS packets,"
            " SUM(CASE WHEN flags LIKE '%SYN%' AND flags NOT LIKE '%ACK%' THEN 1 ELSE 0 END) AS syns"
            " FROM packets WHERE ts >= ? AND dst_port IS NOT NULL"
            " GROUP BY src_ip HAVING ports >= ?",
            (since, threshold),
        )
        findings = []
        for row in rows:
            ip = row["src_ip"]
            if self._skip(ip):
                continue
            severity = "high" if row["ports"] >= threshold * 3 else "medium"
            score = self.storage.bump_reputation(
                ip, self.scoring.get("port_scan", 40), "port_scan"
            )
            finding = {
                "kind": "port_scan",
                "severity": severity,
                "src_ip": ip,
                "title": "Port scan detected from %s" % ip,
                "detail": "%d distinct ports, %d packets, %d SYN-only in %ds"
                % (row["ports"], row["packets"], row["syns"] or 0, window),
                "score": score,
            }
            findings.append(finding)
            self.alerter.dispatch(finding)
        return findings

    def detect_brute_force(self):
        window = self.config.get("detection.brute_force.window_seconds", 300)
        threshold = self.config.get("detection.brute_force.failed_logins", 8)
        since = time.time() - window
        rows = self.storage.query(
            "SELECT src_ip, COUNT(*) AS failures, COUNT(DISTINCT username) AS users,"
            " MAX(service) AS service FROM auth_events"
            " WHERE ts >= ? AND success = 0 GROUP BY src_ip HAVING failures >= ?",
            (since, threshold),
        )
        findings = []
        for row in rows:
            ip = row["src_ip"]
            if self._skip(ip):
                continue
            severity = "critical" if row["failures"] >= threshold * 4 else "high"
            score = self.storage.bump_reputation(
                ip, self.scoring.get("brute_force", 50), "brute_force"
            )
            finding = {
                "kind": "brute_force",
                "severity": severity,
                "src_ip": ip,
                "title": "Brute force attempt from %s" % ip,
                "detail": "%d failed logins against %d usernames on %s in %ds"
                % (row["failures"], row["users"], row["service"] or "unknown", window),
                "score": score,
            }
            findings.append(finding)
            self.alerter.dispatch(finding)
        return findings

    def detect_traffic_spikes(self):
        window = self.config.get("detection.traffic_spike.window_seconds", 60)
        history = self.config.get("detection.traffic_spike.baseline_windows", 10)
        multiplier = self.config.get("detection.traffic_spike.stddev_multiplier", 3.0)
        minimum = self.config.get("detection.traffic_spike.min_events", 50)
        now = time.time()
        start = now - window
        current = self.storage.one(
            "SELECT COUNT(*) AS packets, COALESCE(SUM(length), 0) AS bytes,"
            " COUNT(DISTINCT src_ip) AS sources FROM packets WHERE ts >= ?",
            (start,),
        ) or {"packets": 0, "bytes": 0, "sources": 0}
        self.storage.execute(
            "INSERT INTO traffic_windows (window_start, window_end, packet_count, byte_count, unique_sources)"
            " VALUES (?, ?, ?, ?, ?)",
            (start, now, current["packets"], current["bytes"], current["sources"]),
        )
        baseline = self.storage.query(
            "SELECT packet_count FROM traffic_windows WHERE window_end < ?"
            " ORDER BY window_end DESC LIMIT ?",
            (start, history),
        )
        counts = [row["packet_count"] for row in baseline]
        if len(counts) < 3 or current["packets"] < minimum:
            return []
        mean = statistics.fmean(counts)
        deviation = statistics.pstdev(counts) or 1.0
        limit = mean + multiplier * deviation
        if current["packets"] <= limit:
            return []
        top = self.storage.one(
            "SELECT src_ip, COUNT(*) AS packets FROM packets WHERE ts >= ?"
            " GROUP BY src_ip ORDER BY packets DESC LIMIT 1",
            (start,),
        )
        talker = top["src_ip"] if top else None
        if talker and not self._skip(talker):
            self.storage.bump_reputation(
                talker, self.scoring.get("traffic_spike", 20), "traffic_spike"
            )
        finding = {
            "kind": "traffic_spike",
            "severity": "medium",
            "src_ip": talker,
            "title": "Unusual traffic spike detected",
            "detail": "%d packets in %ds vs baseline mean %.1f (threshold %.1f), top talker %s"
            % (current["packets"], window, mean, limit, talker or "n/a"),
            "score": int(current["packets"]),
        }
        self.alerter.dispatch(finding)
        return [finding]

    def detect_suspicious_ips(self):
        threshold = self.config.get("detection.suspicious_ip.score_threshold", 50)
        window = 900
        since = time.time() - window
        active = self.storage.query(
            "SELECT DISTINCT src_ip FROM packets WHERE ts >= ?"
            " UNION SELECT DISTINCT src_ip FROM auth_events WHERE ts >= ?",
            (since, since),
        )
        for row in active:
            ip = row["src_ip"]
            if self._skip(ip):
                continue
            if self.storage.is_blocklisted(ip):
                self.storage.bump_reputation(
                    ip,
                    self.scoring.get("blocklist_hit", 60),
                    "threat_feed",
                    blocklisted=True,
                )
        rows = self.storage.query(
            "SELECT ip, score, blocklisted, notes FROM ip_reputation"
            " WHERE score >= ? AND last_seen >= ?",
            (threshold, since),
        )
        findings = []
        for row in rows:
            ip = row["ip"]
            if self._skip(ip):
                continue
            severity = "critical" if row["score"] >= 80 else "high"
            finding = {
                "kind": "suspicious_ip",
                "severity": severity,
                "src_ip": ip,
                "title": "Suspicious IP %s (score %d)" % (ip, row["score"]),
                "detail": "blocklisted=%s reasons=%s"
                % (bool(row["blocklisted"]), row["notes"] or "behavioral"),
                "score": row["score"],
            }
            findings.append(finding)
            self.alerter.dispatch(finding)
        return findings


# ---------------------------------------------------------------------------
# Live capture (optional, needs root)
# ---------------------------------------------------------------------------

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}
TCP_FLAGS = [
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
]

AUTH_FAIL_PATTERNS = [
    re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
    ),
    re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"),
    re.compile(r"authentication failure;.*rhost=(?P<ip>[0-9a-fA-F:.]+)(?:\s+user=(?P<user>\S+))?"),
]
AUTH_OK_PATTERN = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)


def decode_flags(value):
    return "|".join(name for bit, name in TCP_FLAGS if value & bit) or "NONE"


def parse_ipv4_packet(data):
    if len(data) < 20:
        return None
    version_ihl = data[0]
    if version_ihl >> 4 != 4:
        return None
    ihl = (version_ihl & 0x0F) * 4
    total_length = struct.unpack("!H", data[2:4])[0]
    proto = data[9]
    record = {
        "ts": time.time(),
        "src_ip": socket.inet_ntoa(data[12:16]),
        "dst_ip": socket.inet_ntoa(data[16:20]),
        "protocol": PROTOCOLS.get(proto, str(proto)),
        "length": total_length or len(data),
        "src_port": None,
        "dst_port": None,
        "flags": None,
    }
    payload = data[ihl:]
    if proto == 6 and len(payload) >= 14:
        record["src_port"], record["dst_port"] = struct.unpack("!HH", payload[0:4])
        record["flags"] = decode_flags(payload[13])
    elif proto == 17 and len(payload) >= 4:
        record["src_port"], record["dst_port"] = struct.unpack("!HH", payload[0:4])
    return record


class PacketSniffer(threading.Thread):
    """Raw-socket sniffer. Uses AF_PACKET on Linux, falls back to raw IP."""

    daemon = True

    def __init__(self, storage, batch_size=25, flush_interval=2.0):
        super().__init__(name="packet-sniffer")
        self.storage = storage
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._stop = threading.Event()
        self._buffer = []
        self._last_flush = time.time()
        self.error = None

    def stop(self):
        self._stop.set()

    def _open_socket(self):
        if hasattr(socket, "AF_PACKET"):
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.settimeout(1.0)
            return sock, True
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sock.settimeout(1.0)
        return sock, False

    def _flush(self, force=False):
        due = time.time() - self._last_flush >= self.flush_interval
        if self._buffer and (force or due or len(self._buffer) >= self.batch_size):
            self.storage.add_packets(self._buffer)
            self._buffer = []
            self._last_flush = time.time()

    def run(self):
        try:
            sock, strip_ethernet = self._open_socket()
        except PermissionError:
            self.error = "raw socket capture requires root privileges"
            print(
                "capture disabled: %s (use --no-capture or run with sudo)" % self.error,
                file=sys.stderr,
                flush=True,
            )
            return
        except OSError as error:
            self.error = str(error)
            print("capture disabled: %s" % error, file=sys.stderr, flush=True)
            return
        try:
            while not self._stop.is_set():
                try:
                    data = sock.recv(65535)
                except socket.timeout:
                    self._flush(force=True)
                    continue
                except OSError:
                    break
                if strip_ethernet:
                    if len(data) < 14 or struct.unpack("!H", data[12:14])[0] != 0x0800:
                        continue
                    data = data[14:]
                record = parse_ipv4_packet(data)
                if record:
                    self._buffer.append(record)
                self._flush()
            self._flush(force=True)
        finally:
            sock.close()


class AuthLogTailer(threading.Thread):
    daemon = True

    def __init__(self, storage, path, poll_interval=2.0):
        super().__init__(name="auth-log-tailer")
        self.storage = storage
        self.path = path
        self.poll_interval = poll_interval
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    @staticmethod
    def parse_line(line):
        ok = AUTH_OK_PATTERN.search(line)
        if ok:
            return {
                "ts": time.time(),
                "src_ip": ok.group("ip"),
                "username": ok.group("user"),
                "service": "sshd",
                "port": int(ok.group("port")),
                "success": True,
            }
        for pattern in AUTH_FAIL_PATTERNS:
            match = pattern.search(line)
            if match:
                groups = match.groupdict()
                port = groups.get("port")
                return {
                    "ts": time.time(),
                    "src_ip": groups.get("ip"),
                    "username": groups.get("user") or "unknown",
                    "service": "sshd",
                    "port": int(port) if port else 22,
                    "success": False,
                }
        return None

    def run(self):
        while not self._stop.is_set() and not os.path.exists(self.path):
            time.sleep(self.poll_interval)
        if self._stop.is_set():
            return
        try:
            handle = open(self.path, "r", encoding="utf-8", errors="ignore")
        except OSError as error:
            print("auth log disabled: %s" % error, file=sys.stderr, flush=True)
            return
        with handle:
            handle.seek(0, os.SEEK_END)
            while not self._stop.is_set():
                line = handle.readline()
                if not line:
                    time.sleep(self.poll_interval)
                    continue
                event = self.parse_line(line)
                if event and event.get("src_ip"):
                    self.storage.add_auth_event(event)


IP_LINE_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$")
IP_ANY_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _valid_ip(candidate):
    parts = candidate.split(".")
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def extract_ips(text):
    found = []
    seen = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        candidate = line.split()[0].split(";")[0].strip()
        if IP_LINE_PATTERN.match(candidate):
            ip = candidate.split("/")[0]
        else:
            match = IP_ANY_PATTERN.search(line)
            ip = match.group(0) if match else None
        if ip and _valid_ip(ip) and ip not in seen:
            seen.add(ip)
            found.append(ip)
    return found


def fetch_feed(url, timeout=30, user_agent="netmon-threatfeed"):
    request = urllib.request.Request(url, headers={"User-Agent": user_agent})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="ignore")


def refresh_feeds(storage, config, verbose=True):
    sources = config.get("threat_feeds.sources", []) or []
    timeout = config.get("threat_feeds.timeout", 30)
    agent = config.get("threat_feeds.user_agent", "netmon-threatfeed")
    total = 0
    for url in sources:
        try:
            text = fetch_feed(url, timeout=timeout, user_agent=agent)
        except Exception as error:
            if verbose:
                print("  %s -> failed (%s)" % (url, error), file=sys.stderr, flush=True)
            continue
        ips = extract_ips(text)
        stored = storage.replace_blocklist([(ip, url) for ip in ips])
        total += stored
        if verbose:
            print("  %s -> %d ips" % (url, stored), flush=True)
    storage.set_state("feeds_last_refresh", time.time())
    return total


def should_refresh_feeds(storage, hours):
    last = float(storage.get_state("feeds_last_refresh", 0) or 0)
    return time.time() - last >= hours * 3600

SUSPECT = ["185.203.116.7", "45.155.205.233", "91.240.118.172"]
NORMAL = ["10.0.0.15", "10.0.0.22", "192.168.1.44", "192.168.1.90"]
TARGET = "10.0.0.5"


def seed_normal_traffic(storage, minutes=20, per_minute=40):
    now = time.time()
    packets = []
    for minute in range(minutes, 0, -1):
        base = now - minute * 60
        for _ in range(per_minute):
            packets.append(
                {
                    "ts": base + random.random() * 60,
                    "src_ip": random.choice(NORMAL),
                    "dst_ip": TARGET,
                    "src_port": random.randint(30000, 60000),
                    "dst_port": random.choice([80, 443, 53, 8080]),
                    "protocol": "TCP",
                    "length": random.randint(200, 1400),
                    "flags": "PSH|ACK",
                }
            )
    return storage.add_packets(packets)


def seed_baseline_windows(storage, windows=10, window_seconds=60, per_window=40):
    """Pre-fill traffic baseline so the spike detector has history on run one."""
    now = time.time()
    rows = []
    for index in range(windows, 0, -1):
        end = now - index * window_seconds
        count = int(per_window * random.uniform(0.85, 1.15))
        rows.append((end - window_seconds, end, count, count * 800, len(NORMAL)))
    storage.executemany(
        "INSERT INTO traffic_windows (window_start, window_end, packet_count, byte_count, unique_sources)"
        " VALUES (?, ?, ?, ?, ?)",
        rows,
    )
    return len(rows)


def seed_port_scan(storage, ip=None, ports=80):
    src = ip or SUSPECT[0]
    now = time.time()
    storage.add_packets(
        [
            {
                "ts": now - random.random() * 30,
                "src_ip": src,
                "dst_ip": TARGET,
                "src_port": random.randint(40000, 60000),
                "dst_port": port,
                "protocol": "TCP",
                "length": 60,
                "flags": "SYN",
            }
            for port in range(1, ports + 1)
        ]
    )
    return src


def seed_brute_force(storage, ip=None, attempts=40):
    src = ip or SUSPECT[1]
    now = time.time()
    storage.add_auth_events(
        [
            {
                "ts": now - index * 3,
                "src_ip": src,
                "username": random.choice(["root", "admin", "ubuntu", "test"]),
                "service": "sshd",
                "port": 22,
                "success": False,
            }
            for index in range(attempts)
        ]
    )
    return src


def seed_traffic_spike(storage, ip=None, packets=4000):
    src = ip or SUSPECT[2]
    now = time.time()
    storage.add_packets(
        [
            {
                "ts": now - random.random() * 30,
                "src_ip": src,
                "dst_ip": TARGET,
                "src_port": random.randint(1024, 65535),
                "dst_port": 443,
                "protocol": "UDP",
                "length": random.randint(800, 1500),
                "flags": None,
            }
            for _ in range(packets)
        ]
    )
    return src


def seed_blocklist(storage):
    storage.replace_blocklist([(ip, "simulated-feed") for ip in SUSPECT])
    return SUSPECT


def seed_all(storage):
    seed_normal_traffic(storage)
    seed_baseline_windows(storage)
    seed_port_scan(storage)
    seed_brute_force(storage)
    seed_traffic_spike(storage)
    seed_blocklist(storage)



GRAFANA_DATASOURCE = """apiVersion: 1

datasources:
  - name: netmon-sqlite
    uid: netmon-sqlite
    type: frser-sqlite-datasource
    access: proxy
    isDefault: true
    jsonData:
      path: %(database)s
"""

GRAFANA_DASHBOARD = {
    "title": "netmon",
    "uid": "netmon-overview",
    "timezone": "browser",
    "schemaVersion": 39,
    "time": {"from": "now-24h", "to": "now"},
    "refresh": "1m",
    "panels": [
        {
            "type": "stat",
            "title": "Alerts (24h)",
            "gridPos": {"h": 4, "w": 6, "x": 0, "y": 0},
            "datasource": {"type": "frser-sqlite-datasource", "uid": "netmon-sqlite"},
            "targets": [
                {
                    "refId": "A",
                    "queryType": "table",
                    "rawQueryText": "SELECT COUNT(*) AS alerts FROM alerts WHERE ts >= strftime('%s','now') - 86400",
                }
            ],
        },
        {
            "type": "stat",
            "title": "Suspicious IPs",
            "gridPos": {"h": 4, "w": 6, "x": 6, "y": 0},
            "datasource": {"type": "frser-sqlite-datasource", "uid": "netmon-sqlite"},
            "targets": [
                {
                    "refId": "A",
                    "queryType": "table",
                    "rawQueryText": "SELECT COUNT(*) AS suspicious FROM ip_reputation WHERE score >= 50",
                }
            ],
        },
        {
            "type": "stat",
            "title": "Blocklist entries",
            "gridPos": {"h": 4, "w": 6, "x": 12, "y": 0},
            "datasource": {"type": "frser-sqlite-datasource", "uid": "netmon-sqlite"},
            "targets": [
                {
                    "refId": "A",
                    "queryType": "table",
                    "rawQueryText": "SELECT COUNT(*) AS blocklist FROM blocklist",
                }
            ],
        },
        {
            "type": "stat",
            "title": "Failed logins (24h)",
            "gridPos": {"h": 4, "w": 6, "x": 18, "y": 0},
            "datasource": {"type": "frser-sqlite-datasource", "uid": "netmon-sqlite"},
            "targets": [
                {
                    "refId": "A",
                    "queryType": "table",
                    "rawQueryText": "SELECT COUNT(*) AS failures FROM auth_events WHERE success = 0 AND ts >= strftime('%s','now') - 86400",
                }
            ],
        },
        {
            "type": "timeseries",
            "title": "Packet volume",
            "gridPos": {"h": 8, "w": 12, "x": 0, "y": 4},
            "datasource": {"type": "frser-sqlite-datasource", "uid": "netmon-sqlite"},
            "targets": [
                {
                    "refId": "A",
                    "queryType": "time series",
                    "timeColumns": ["time"],
                    "rawQueryText": "SELECT CAST(window_end AS INTEGER) * 1000 AS time, packet_count AS packets FROM traffic_windows ORDER BY window_end",
                }
            ],
        },
        {
            "type": "piechart",
            "title": "Alerts by type",
            "gridPos": {"h": 8, "w": 12, "x": 12, "y": 4},
            "datasource": {"type": "frser-sqlite-datasource", "uid": "netmon-sqlite"},
            "targets": [
                {
                    "refId": "A",
                    "queryType": "table",
                    "rawQueryText": "SELECT kind, COUNT(*) AS total FROM alerts GROUP BY kind ORDER BY total DESC",
                }
            ],
        },
        {
            "type": "table",
            "title": "Top suspicious IPs",
            "gridPos": {"h": 8, "w": 12, "x": 0, "y": 12},
            "datasource": {"type": "frser-sqlite-datasource", "uid": "netmon-sqlite"},
            "targets": [
                {
                    "refId": "A",
                    "queryType": "table",
                    "rawQueryText": "SELECT ip, score, blocklisted, notes FROM ip_reputation ORDER BY score DESC LIMIT 20",
                }
            ],
        },
        {
            "type": "table",
            "title": "Recent alerts",
            "gridPos": {"h": 8, "w": 12, "x": 12, "y": 12},
            "datasource": {"type": "frser-sqlite-datasource", "uid": "netmon-sqlite"},
            "targets": [
                {
                    "refId": "A",
                    "queryType": "table",
                    "rawQueryText": "SELECT datetime(ts,'unixepoch') AS time, severity, kind, src_ip, title FROM alerts ORDER BY ts DESC LIMIT 50",
                }
            ],
        },
    ],
}


def build(args):
    config = load_config(getattr(args, "config", None))
    storage = Storage(config.get("database"))
    alerter = Alerter(storage, config)
    engine = DetectionEngine(storage, config, alerter)
    return config, storage, alerter, engine


def print_findings(findings):
    for finding in findings:
        print(
            "  %-8s %-14s %s"
            % (finding["severity"].upper(), finding["kind"], finding["title"])
        )
    print("  %d finding(s)" % len(findings))


def print_report(storage, hours):
    since = time.time() - hours * 3600
    rows = storage.query(
        "SELECT kind, severity, COUNT(*) AS total FROM alerts WHERE ts >= ?"
        " GROUP BY kind, severity ORDER BY total DESC",
        (since,),
    )
    print("\nalerts in last %dh" % hours)
    if not rows:
        print("  (none)")
    for row in rows:
        print("  %-14s %-8s %d" % (row["kind"], row["severity"], row["total"]))
    top = storage.query(
        "SELECT ip, score, blocklisted FROM ip_reputation ORDER BY score DESC LIMIT 10"
    )
    print("\ntop suspicious ips")
    if not top:
        print("  (none)")
    for row in top:
        print(
            "  %-18s score=%-4d blocklisted=%s"
            % (row["ip"], row["score"], bool(row["blocklisted"]))
        )


def cmd_init(args):
    config, storage, _, _ = build(args)
    print("database ready at %s" % config.get("database"))
    if config.source:
        print("config loaded from %s" % config.source)
    storage.close()


def cmd_demo(args):
    config, storage, _, engine = build(args)
    print("netmon %s demo" % __version__)
    print("database: %s" % config.get("database"))
    print("config:   %s" % (config.source or "built-in defaults"))
    print("\nseeding simulated traffic...")
    seed_all(storage)
    print("running detections...")
    findings = engine.run_cycle()
    print_findings(findings)
    print_report(storage, args.hours)
    print(
        "\nnext: python3 %s run --no-capture   (continuous detection)"
        % os.path.basename(__file__)
    )
    storage.close()


def cmd_scan_once(args):
    _, storage, _, engine = build(args)
    print_findings(engine.run_cycle())
    storage.close()


def cmd_run(args):
    config, storage, _, engine = build(args)
    workers = []
    if not args.no_capture:
        sniffer = PacketSniffer(storage)
        sniffer.start()
        workers.append(sniffer)
        log_path = config.get("capture.log_file")
        if log_path:
            tailer = AuthLogTailer(
                storage, log_path, config.get("capture.poll_interval", 2)
            )
            tailer.start()
            workers.append(tailer)

    running = {"value": True}

    def shutdown(signum, frame):
        running["value"] = False

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    feed_hours = config.get("threat_feeds.refresh_hours", 6)
    print(
        "monitoring started (capture=%s, detection interval %ss). ctrl-c to stop."
        % (not args.no_capture, args.interval),
        flush=True,
    )
    while running["value"]:
        try:
            if feed_hours and should_refresh_feeds(storage, feed_hours):
                print("refreshing threat feeds...", flush=True)
                refresh_feeds(storage, config)
            engine.run_cycle()
        except Exception as error:
            print("detection cycle failed: %s" % error, file=sys.stderr, flush=True)
        for _ in range(int(args.interval * 10)):
            if not running["value"]:
                break
            time.sleep(0.1)

    for worker in workers:
        worker.stop()
    storage.purge(args.retention_days)
    storage.close()
    print("monitoring stopped", flush=True)


def cmd_feeds(args):
    config, storage, _, _ = build(args)
    print("refreshing %d feed(s)..." % len(config.get("threat_feeds.sources", []) or []))
    refresh_feeds(storage, config)
    total = storage.one("SELECT COUNT(*) AS total FROM blocklist")
    print("blocklist entries: %s" % total["total"])
    storage.close()


def cmd_report(args):
    _, storage, _, _ = build(args)
    print_report(storage, args.hours)
    storage.close()


def cmd_config(args):
    config = load_config(getattr(args, "config", None))
    try:
        import yaml

        print(yaml.safe_dump(config.raw, sort_keys=False).rstrip())
    except ImportError:
        print(json.dumps(config.raw, indent=2))


def cmd_grafana(args):
    config = load_config(getattr(args, "config", None))
    target = os.path.abspath(args.directory)
    os.makedirs(target, exist_ok=True)
    datasource_path = os.path.join(target, "datasource.yaml")
    dashboard_path = os.path.join(target, "dashboard.json")
    with open(datasource_path, "w", encoding="utf-8") as handle:
        handle.write(GRAFANA_DATASOURCE % {"database": os.path.abspath(config.get("database"))})
    with open(dashboard_path, "w", encoding="utf-8") as handle:
        json.dump(GRAFANA_DASHBOARD, handle, indent=2)
        handle.write("\n")
    print("wrote %s" % datasource_path)
    print("wrote %s" % dashboard_path)
    print("install the datasource plugin: grafana-cli plugins install frser-sqlite-datasource")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="netmon.py",
        description="single-file network monitoring system (run with no arguments for the demo)",
    )
    parser.add_argument("-c", "--config", default=None, help="optional config file")
    parser.add_argument("-V", "--version", action="version", version="netmon " + __version__)
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("init", help="create the database").set_defaults(func=cmd_init)

    demo = sub.add_parser("demo", help="seed simulated traffic, detect, report")
    demo.add_argument("--hours", type=int, default=24)
    demo.set_defaults(func=cmd_demo)
    sub.add_parser("simulate", help="alias for demo").set_defaults(func=cmd_demo, hours=24)

    run = sub.add_parser("run", help="continuous monitoring")
    run.add_argument("--interval", type=float, default=15.0)
    run.add_argument("--retention-days", type=int, default=7)
    run.add_argument("--no-capture", action="store_true", help="skip raw capture (no root)")
    run.set_defaults(func=cmd_run)

    sub.add_parser("scan-once", help="one detection cycle").set_defaults(func=cmd_scan_once)
    sub.add_parser("feeds", help="refresh threat feed blocklists").set_defaults(func=cmd_feeds)

    report = sub.add_parser("report", help="alert summary")
    report.add_argument("--hours", type=int, default=24)
    report.set_defaults(func=cmd_report)

    sub.add_parser("config", help="print effective configuration").set_defaults(func=cmd_config)

    grafana = sub.add_parser("grafana", help="write Grafana provisioning files")
    grafana.add_argument("directory", nargs="?", default="grafana")
    grafana.set_defaults(func=cmd_grafana)

    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        args.func = cmd_demo
        args.hours = 24
    args.func(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\ninterrupted", flush=True)
