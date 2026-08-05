import os
import re
import socket
import struct
import threading
import time

AUTH_FAIL_PATTERNS = [
    re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"),
    re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"),
    re.compile(r"authentication failure;.*rhost=(?P<ip>[0-9a-fA-F:.]+)(?:\s+user=(?P<user>\S+))?"),
]
AUTH_OK_PATTERN = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}
TCP_FLAGS = [
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
]


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
    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])
    record = {
        "ts": time.time(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": PROTOCOLS.get(proto, str(proto)),
        "length": total_length or len(data),
        "src_port": None,
        "dst_port": None,
        "flags": None,
    }
    payload = data[ihl:]
    if proto == 6 and len(payload) >= 14:
        src_port, dst_port = struct.unpack("!HH", payload[0:4])
        record["src_port"] = src_port
        record["dst_port"] = dst_port
        record["flags"] = decode_flags(payload[13])
    elif proto == 17 and len(payload) >= 4:
        src_port, dst_port = struct.unpack("!HH", payload[0:4])
        record["src_port"] = src_port
        record["dst_port"] = dst_port
    return record


class PacketSniffer(threading.Thread):
    daemon = True

    def __init__(self, storage, batch_size=25, flush_interval=2.0):
        super().__init__(name="packet-sniffer")
        self.storage = storage
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._stop = threading.Event()
        self._buffer = []
        self._last_flush = time.time()

    def stop(self):
        self._stop.set()

    def _flush(self, force=False):
        due = time.time() - self._last_flush >= self.flush_interval
        if self._buffer and (force or due or len(self._buffer) >= self.batch_size):
            self.storage.add_packets(self._buffer)
            self._buffer = []
            self._last_flush = time.time()

    def run(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.settimeout(1.0)
        except PermissionError:
            raise SystemExit("raw socket capture requires root privileges")
        while not self._stop.is_set():
            try:
                data = sock.recv(65535)
            except socket.timeout:
                self._flush(force=True)
                continue
            record = parse_ipv4_packet(data)
            if record:
                self._buffer.append(record)
            self._flush()
        self._flush(force=True)
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
        with open(self.path, "r", encoding="utf-8", errors="ignore") as handle:
            handle.seek(0, os.SEEK_END)
            while not self._stop.is_set():
                line = handle.readline()
                if not line:
                    time.sleep(self.poll_interval)
                    continue
                event = self.parse_line(line)
                if event and event.get("src_ip"):
                    self.storage.add_auth_event(event)
