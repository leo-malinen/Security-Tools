import statistics
import time


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
            score = self.storage.bump_reputation(ip, self.scoring.get("port_scan", 40), "port_scan")
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
            score = self.storage.bump_reputation(ip, self.scoring.get("brute_force", 50), "brute_force")
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
            self.storage.bump_reputation(talker, self.scoring.get("traffic_spike", 20), "traffic_spike")
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
                    ip, self.scoring.get("blocklist_hit", 60), "threat_feed", blocklisted=True
                )
        rows = self.storage.query(
            "SELECT ip, score, blocklisted, notes FROM ip_reputation WHERE score >= ? AND last_seen >= ?",
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
                "detail": "blocklisted=%s reasons=%s" % (bool(row["blocklisted"]), row["notes"] or "behavioral"),
                "score": row["score"],
            }
            findings.append(finding)
            self.alerter.dispatch(finding)
        return findings
