from __future__ import annotations
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Set, Tuple
from .models import Packet
from .utils import base_domain, is_private_ip, label_entropy, shannon_entropy
SEVERITY_ORDER = {'info': 0, 'low': 1, 'medium': 2, 'high': 3}
SUSPICIOUS_PORTS: Dict[int, str] = {23: 'telnet (cleartext remote shell)', 1337: 'common reverse-shell port', 2323: 'telnet alternate (IoT botnets)', 3389: 'RDP exposed', 4444: 'Metasploit default handler', 4445: 'Metasploit alternate handler', 5554: 'Sasser/backdoor family', 5555: 'ADB / android debug bridge', 6666: 'IRC bot channel', 6667: 'IRC (botnet C2)', 6697: 'IRC over TLS (botnet C2)', 9001: 'Tor ORPort / misc C2', 9050: 'Tor SOCKS proxy', 31337: 'Back Orifice / elite backdoor'}
CLEARTEXT_CREDENTIAL_PORTS = {21: 'FTP', 23: 'telnet', 110: 'POP3', 143: 'IMAP', 143: 'IMAP'}
CREDENTIAL_FIELD_RE = re.compile(b'(password|passwd|pwd|pass|secret|api[_-]?key|token|auth)=([^&\\s]{1,80})', re.IGNORECASE)
FTP_CREDENTIAL_RE = re.compile(b'^(USER|PASS)\\s+(\\S+)', re.IGNORECASE | re.MULTILINE)

@dataclass
class Alert:
    ts: float
    severity: str
    rule: str
    message: str
    src: Optional[str] = None
    dst: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {'ts': self.ts, 'severity': self.severity, 'rule': self.rule, 'message': self.message, 'src': self.src, 'dst': self.dst, 'evidence': self.evidence}

@dataclass
class DetectorConfig:
    port_scan_ports: int = 20
    port_scan_window: float = 10.0
    host_sweep_hosts: int = 15
    host_sweep_window: float = 10.0
    syn_flood_count: int = 120
    syn_flood_window: float = 5.0
    dns_tunnel_subdomains: int = 30
    dns_tunnel_window: float = 60.0
    dns_long_label: int = 45
    dns_entropy: float = 3.6
    icmp_payload_bytes: int = 128
    icmp_entropy: float = 6.0
    exfil_bytes: int = 5 * 1024 * 1024
    exfil_window: float = 60.0
    cooldown: float = 30.0

class Detector:

    def __init__(self, config: Optional[DetectorConfig]=None):
        self.config = config or DetectorConfig()
        self.alerts: List[Alert] = []
        self._syn_targets: Dict[str, Deque[Tuple[float, str, int]]] = defaultdict(deque)
        self._sweep_targets: Dict[str, Deque[Tuple[float, str]]] = defaultdict(deque)
        self._syn_flood: Dict[Tuple[str, int], Deque[float]] = defaultdict(deque)
        self._dns_subdomains: Dict[Tuple[str, str], Deque[Tuple[float, str]]] = defaultdict(deque)
        self._volume: Dict[Tuple[str, str], Deque[Tuple[float, int]]] = defaultdict(deque)
        self._last_fired: Dict[Tuple[str, str], float] = {}

    def feed(self, packet: Packet) -> List[Alert]:
        found: List[Alert] = []
        if packet.ip is None and packet.arp is None:
            return found
        if packet.tcp is not None:
            found += self._check_stealth_scan(packet)
            found += self._check_port_scan(packet)
            found += self._check_syn_flood(packet)
        if packet.icmp is not None:
            found += self._check_icmp_tunnel(packet)
            found += self._check_host_sweep(packet)
        if packet.dns is not None:
            found += self._check_dns_tunnel(packet)
        if packet.http is not None:
            found += self._check_http_credentials(packet)
        found += self._check_cleartext_protocols(packet)
        found += self._check_suspicious_ports(packet)
        found += self._check_volume(packet)
        self.alerts.extend(found)
        return found

    def _cooldown_ok(self, rule: str, key: str, ts: float) -> bool:
        last = self._last_fired.get((rule, key))
        if last is not None and ts - last < self.config.cooldown:
            return False
        self._last_fired[rule, key] = ts
        return True

    @staticmethod
    def _trim(window: Deque, ts: float, span: float) -> None:
        cutoff = ts - span
        while window and window[0][0] < cutoff:
            window.popleft()

    @staticmethod
    def _trim_scalar(window: Deque[float], ts: float, span: float) -> None:
        cutoff = ts - span
        while window and window[0] < cutoff:
            window.popleft()

    def _check_stealth_scan(self, packet: Packet) -> List[Alert]:
        assert packet.tcp is not None
        signature = packet.tcp.scan_signature
        if signature is None:
            return []
        src = packet.src_ip or '?'
        if not self._cooldown_ok('stealth-scan', f'{src}:{signature}', packet.ts):
            return []
        return [Alert(ts=packet.ts, severity='high', rule='stealth-scan', message=f'{signature} from {src} (flags {packet.tcp.flag_string})', src=src, dst=packet.dst_ip, evidence={'flags': packet.tcp.flag_string, 'dport': packet.dport})]

    def _check_port_scan(self, packet: Packet) -> List[Alert]:
        assert packet.tcp is not None
        if not packet.tcp.is_syn_only:
            return []
        src = packet.src_ip
        dst = packet.dst_ip
        if src is None or dst is None or packet.dport is None:
            return []
        window = self._syn_targets[src]
        window.append((packet.ts, dst, packet.dport))
        self._trim(window, packet.ts, self.config.port_scan_window)
        per_host: Dict[str, Set[int]] = defaultdict(set)
        for _, host, port in window:
            per_host[host].add(port)
        alerts = []
        for host, ports in per_host.items():
            if len(ports) >= self.config.port_scan_ports and self._cooldown_ok('port-scan', f'{src}->{host}', packet.ts):
                alerts.append(Alert(ts=packet.ts, severity='high', rule='port-scan', message=f'{src} probed {len(ports)} ports on {host} in {self.config.port_scan_window:.0f}s', src=src, dst=host, evidence={'distinct_ports': len(ports), 'sample_ports': sorted(ports)[:15]}))
        distinct_hosts = {host for _, host, _ in window}
        if len(distinct_hosts) >= self.config.host_sweep_hosts and self._cooldown_ok('host-sweep', src, packet.ts):
            alerts.append(Alert(ts=packet.ts, severity='medium', rule='host-sweep', message=f'{src} sent SYNs to {len(distinct_hosts)} distinct hosts', src=src, evidence={'hosts': len(distinct_hosts)}))
        return alerts

    def _check_host_sweep(self, packet: Packet) -> List[Alert]:
        assert packet.icmp is not None
        if packet.icmp.type not in (8, 128):
            return []
        src, dst = (packet.src_ip, packet.dst_ip)
        if src is None or dst is None:
            return []
        window = self._sweep_targets[src]
        window.append((packet.ts, dst))
        self._trim(window, packet.ts, self.config.host_sweep_window)
        hosts = {host for _, host in window}
        if len(hosts) >= self.config.host_sweep_hosts and self._cooldown_ok('ping-sweep', src, packet.ts):
            return [Alert(ts=packet.ts, severity='medium', rule='ping-sweep', message=f'{src} pinged {len(hosts)} distinct hosts', src=src, evidence={'hosts': len(hosts)})]
        return []

    def _check_syn_flood(self, packet: Packet) -> List[Alert]:
        assert packet.tcp is not None
        if not packet.tcp.is_syn_only or packet.dst_ip is None or packet.dport is None:
            return []
        key = (packet.dst_ip, packet.dport)
        window = self._syn_flood[key]
        window.append(packet.ts)
        self._trim_scalar(window, packet.ts, self.config.syn_flood_window)
        if len(window) >= self.config.syn_flood_count and self._cooldown_ok('syn-flood', f'{key[0]}:{key[1]}', packet.ts):
            rate = len(window) / max(self.config.syn_flood_window, 1e-06)
            return [Alert(ts=packet.ts, severity='high', rule='syn-flood', message=f'{len(window)} SYNs to {packet.dst_ip}:{packet.dport} in {self.config.syn_flood_window:.0f}s (~{rate:.0f}/s)', dst=packet.dst_ip, evidence={'syn_count': len(window), 'port': packet.dport})]
        return []

    def _check_dns_tunnel(self, packet: Packet) -> List[Alert]:
        assert packet.dns is not None
        if packet.dns.is_response or not packet.dns.questions:
            return []
        alerts: List[Alert] = []
        src = packet.src_ip or '?'
        for question in packet.dns.questions:
            name = question.name
            if not name:
                continue
            labels = name.split('.')
            longest = max((len(label) for label in labels), default=0)
            entropy = label_entropy(labels[0]) if labels else 0.0
            if longest >= self.config.dns_long_label and entropy >= self.config.dns_entropy and self._cooldown_ok('dns-tunnel', f'{src}:{base_domain(name)}', packet.ts):
                alerts.append(Alert(ts=packet.ts, severity='high', rule='dns-tunnel', message=f'high-entropy DNS label ({longest} chars, {entropy:.1f} bits/char) queried by {src}: {name[:70]}', src=src, dst=packet.dst_ip, evidence={'qname': name, 'label_length': longest, 'entropy': round(entropy, 2), 'qtype': question.type_name}))
            domain = base_domain(name)
            window = self._dns_subdomains[src, domain]
            window.append((packet.ts, name))
            self._trim(window, packet.ts, self.config.dns_tunnel_window)
            unique = {n for _, n in window}
            if len(unique) >= self.config.dns_tunnel_subdomains and self._cooldown_ok('dns-tunnel-volume', f'{src}:{domain}', packet.ts):
                alerts.append(Alert(ts=packet.ts, severity='high', rule='dns-tunnel-volume', message=f'{src} queried {len(unique)} unique subdomains of {domain} in {self.config.dns_tunnel_window:.0f}s', src=src, evidence={'domain': domain, 'unique_subdomains': len(unique)}))
            if question.qtype in (10, 16, 255) and self._cooldown_ok('dns-rare-qtype', f'{src}:{question.type_name}', packet.ts):
                alerts.append(Alert(ts=packet.ts, severity='low', rule='dns-rare-qtype', message=f'{src} issued a {question.type_name} query for {name[:60]}', src=src, evidence={'qtype': question.type_name, 'qname': name}))
        return alerts

    def _check_icmp_tunnel(self, packet: Packet) -> List[Alert]:
        assert packet.icmp is not None
        if packet.icmp.type not in (0, 8, 128, 129):
            return []
        payload = packet.payload
        size = len(payload)
        if size < self.config.icmp_payload_bytes:
            return []
        entropy = shannon_entropy(payload)
        src = packet.src_ip or '?'
        if entropy < self.config.icmp_entropy:
            return []
        if not self._cooldown_ok('icmp-tunnel', f'{src}->{packet.dst_ip}', packet.ts):
            return []
        return [Alert(ts=packet.ts, severity='high', rule='icmp-tunnel', message=f'oversized high-entropy ICMP payload {size}B ({entropy:.1f} bits/byte) {src} -> {packet.dst_ip}', src=src, dst=packet.dst_ip, evidence={'payload_bytes': size, 'entropy': round(entropy, 2)})]

    def _check_http_credentials(self, packet: Packet) -> List[Alert]:
        assert packet.http is not None
        http = packet.http
        alerts: List[Alert] = []
        src = packet.src_ip or '?'
        target = f'{packet.dst_ip}:{packet.dport}'
        auth = http.headers.get('authorization', '')
        if auth.lower().startswith('basic ') and self._cooldown_ok('cleartext-credentials', f'{src}->{target}:basic', packet.ts):
            alerts.append(Alert(ts=packet.ts, severity='high', rule='cleartext-credentials', message=f'HTTP Basic auth sent unencrypted from {src} to {target}', src=src, dst=packet.dst_ip, evidence={'header': 'Authorization: Basic <redacted>', 'path': http.path}))
        if http.kind == 'request' and http.body_length:
            match = CREDENTIAL_FIELD_RE.search(packet.payload)
            if match and self._cooldown_ok('cleartext-credentials', f'{src}->{target}:form', packet.ts):
                field_name = match.group(1).decode('latin-1', 'replace')
                alerts.append(Alert(ts=packet.ts, severity='high', rule='cleartext-credentials', message=f"unencrypted '{field_name}' field posted from {src} to {target}{http.path or ''}", src=src, dst=packet.dst_ip, evidence={'field': field_name, 'path': http.path}))
        return alerts

    def _check_cleartext_protocols(self, packet: Packet) -> List[Alert]:
        if packet.tcp is None or not packet.payload:
            return []
        port = packet.dport if packet.dport in CLEARTEXT_CREDENTIAL_PORTS else packet.sport
        if port not in CLEARTEXT_CREDENTIAL_PORTS:
            return []
        match = FTP_CREDENTIAL_RE.search(packet.payload)
        if not match:
            return []
        src = packet.src_ip or '?'
        if not self._cooldown_ok('cleartext-credentials', f'{src}:{port}', packet.ts):
            return []
        verb = match.group(1).decode('latin-1', 'replace').upper()
        return [Alert(ts=packet.ts, severity='high', rule='cleartext-credentials', message=f'{CLEARTEXT_CREDENTIAL_PORTS[port]} {verb} command in cleartext {src} -> {packet.dst_ip}:{port}', src=src, dst=packet.dst_ip, evidence={'protocol': CLEARTEXT_CREDENTIAL_PORTS[port], 'command': verb})]

    def _check_suspicious_ports(self, packet: Packet) -> List[Alert]:
        if packet.tcp is None and packet.udp is None:
            return []
        alerts = []
        for port, direction in ((packet.dport, 'destination'), (packet.sport, 'source')):
            if port in SUSPICIOUS_PORTS:
                key = f'{packet.src_ip}->{packet.dst_ip}:{port}'
                if not self._cooldown_ok('suspicious-port', key, packet.ts):
                    continue
                alerts.append(Alert(ts=packet.ts, severity='medium', rule='suspicious-port', message=f'traffic on {direction} port {port} - {SUSPICIOUS_PORTS[port]} ({packet.src_ip} -> {packet.dst_ip})', src=packet.src_ip, dst=packet.dst_ip, evidence={'port': port, 'note': SUSPICIOUS_PORTS[port]}))
                break
        return alerts

    def _check_volume(self, packet: Packet) -> List[Alert]:
        src, dst = (packet.src_ip, packet.dst_ip)
        if src is None or dst is None:
            return []
        if not is_private_ip(src) or is_private_ip(dst):
            return []
        key = (src, dst)
        window = self._volume[key]
        window.append((packet.ts, packet.wire_length))
        self._trim(window, packet.ts, self.config.exfil_window)
        total = sum((size for _, size in window))
        if total >= self.config.exfil_bytes and self._cooldown_ok('data-egress', f'{src}->{dst}', packet.ts):
            mb = total / (1024 * 1024)
            return [Alert(ts=packet.ts, severity='medium', rule='data-egress', message=f'{mb:.1f} MB sent from {src} to external host {dst} in {self.config.exfil_window:.0f}s', src=src, dst=dst, evidence={'bytes': total})]
        return []
