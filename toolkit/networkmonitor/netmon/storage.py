import sqlite3
import threading
import time

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
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

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

    def add_packet(self, packet):
        self.execute(
            "INSERT INTO packets (ts, src_ip, dst_ip, src_port, dst_port, protocol, length, flags)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                packet.get("ts", time.time()),
                packet.get("src_ip"),
                packet.get("dst_ip"),
                packet.get("src_port"),
                packet.get("dst_port"),
                packet.get("protocol"),
                packet.get("length", 0),
                packet.get("flags"),
            ),
        )

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
                (ip, points, now, now, 1 if blocklisted else 0, note or ""),
            )
            return points
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
