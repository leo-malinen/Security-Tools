from __future__ import annotations
import shutil
import sys
import time
from collections import Counter, deque
from typing import Deque, Dict, List, Optional, Tuple
from .models import Packet
from .utils import human_bytes, human_rate
CLEAR_SCREEN = '\x1b[2J\x1b[H'
BOLD = '\x1b[1m'
DIM = '\x1b[2m'
RESET = '\x1b[0m'
RED = '\x1b[31m'
YELLOW = '\x1b[33m'
CYAN = '\x1b[36m'

class Statistics:

    def __init__(self, rate_window: float=10.0, top_n: int=8):
        self.start_time = time.time()
        self.rate_window = rate_window
        self.top_n = top_n
        self.packets = 0
        self.bytes = 0
        self.filtered_out = 0
        self.decode_errors = 0
        self.protocols: Counter = Counter()
        self.ethertypes: Counter = Counter()
        self.talkers: Counter = Counter()
        self.conversations: Counter = Counter()
        self.dst_ports: Counter = Counter()
        self.tcp_flags: Counter = Counter()
        self.dns_queries: Counter = Counter()
        self.http_hosts: Counter = Counter()
        self.http_methods: Counter = Counter()
        self.icmp_types: Counter = Counter()
        self._recent: Deque[Tuple[float, int]] = deque()
        self.last_packet_ts: Optional[float] = None

    def add(self, packet: Packet) -> None:
        self.packets += 1
        self.bytes += packet.wire_length
        self.last_packet_ts = packet.ts
        if packet.errors:
            self.decode_errors += 1
        self._recent.append((packet.ts, packet.wire_length))
        cutoff = packet.ts - self.rate_window
        while self._recent and self._recent[0][0] < cutoff:
            self._recent.popleft()
        self.protocols[packet.protocol] += 1
        if packet.eth:
            self.ethertypes[f'0x{packet.eth.ethertype:04x}'] += 1
        src, dst = (packet.src_ip, packet.dst_ip)
        if src:
            self.talkers[src] += packet.wire_length
        if src and dst:
            key = ' <-> '.join(sorted([src, dst]))
            self.conversations[key] += packet.wire_length
        if packet.dport is not None:
            proto = packet.transport_protocol or '?'
            self.dst_ports[f'{proto}/{packet.dport}'] += 1
        if packet.tcp:
            self.tcp_flags[packet.tcp.flag_string] += 1
        if packet.icmp:
            self.icmp_types[packet.icmp.type_name] += 1
        if packet.dns and packet.dns.questions and (not packet.dns.is_response):
            q = packet.dns.questions[0]
            self.dns_queries[f'{q.type_name} {q.name}'] += 1
        if packet.http:
            if packet.http.kind == 'request':
                self.http_methods[packet.http.method or '?'] += 1
                if packet.http.host:
                    self.http_hosts[packet.http.host] += 1

    def skip(self) -> None:
        self.filtered_out += 1

    @property
    def duration(self) -> float:
        return max(time.time() - self.start_time, 1e-06)

    @property
    def packets_per_second(self) -> float:
        if len(self._recent) < 2:
            return 0.0
        span = self._recent[-1][0] - self._recent[0][0]
        return len(self._recent) / span if span > 0 else 0.0

    @property
    def bytes_per_second(self) -> float:
        if len(self._recent) < 2:
            return 0.0
        span = self._recent[-1][0] - self._recent[0][0]
        total = sum((size for _, size in self._recent))
        return total / span if span > 0 else 0.0

    @property
    def average_packet_size(self) -> float:
        return self.bytes / self.packets if self.packets else 0.0

def _bar(count: int, total: int, width: int=18) -> str:
    if total <= 0:
        return ' ' * width
    filled = int(round(count / total * width))
    return '#' * filled + '.' * (width - filled)

def _column(title: str, rows: List[Tuple[str, str]], width: int) -> List[str]:
    lines = [f'{BOLD}{title}{RESET}']
    if not rows:
        lines.append(f'{DIM}  (none){RESET}')
    for label, value in rows:
        room = width - len(value) - 3
        if room < 8:
            room = 8
        label = label if len(label) <= room else label[:room - 1] + '~'
        lines.append(f'  {label:<{room}} {value}')
    return lines

def render_dashboard(stats: Statistics, alerts: List, source: str, filter_text: Optional[str], pcap_path: Optional[str], pcap_count: int=0) -> str:
    width = min(shutil.get_terminal_size((100, 30)).columns, 120)
    out: List[str] = []
    rule = '=' * width
    out.append(f'{BOLD}{CYAN}netscope{RESET}  source={source}  elapsed={stats.duration:6.1f}s')
    if filter_text:
        out.append(f'{DIM}filter: {filter_text}{RESET}')
    out.append(rule)
    out.append(f'packets {BOLD}{stats.packets}{RESET}   volume {BOLD}{human_bytes(stats.bytes)}{RESET}   rate {BOLD}{stats.packets_per_second:.1f} pkt/s{RESET} / {human_rate(stats.bytes_per_second)}   avg {stats.average_packet_size:.0f}B')
    extra = []
    if stats.filtered_out:
        extra.append(f'filtered out {stats.filtered_out}')
    if stats.decode_errors:
        extra.append(f'decode errors {stats.decode_errors}')
    if pcap_path:
        extra.append(f'pcap {pcap_path} ({pcap_count} pkts)')
    if extra:
        out.append(DIM + '   '.join(extra) + RESET)
    out.append(rule)
    out.append(f'{BOLD}Protocols{RESET}')
    total = stats.packets or 1
    for name, count in stats.protocols.most_common(8):
        pct = count / total * 100
        out.append(f'  {name:<10} {count:>7}  {pct:5.1f}%  {_bar(count, total)}')
    out.append('')
    half = max(width // 2 - 2, 30)
    left = _column('Top talkers (by bytes)', [(ip, human_bytes(b)) for ip, b in stats.talkers.most_common(stats.top_n)], half)
    right = _column('Top destination ports', [(port, str(count)) for port, count in stats.dst_ports.most_common(stats.top_n)], half)
    for line in _side_by_side(left, right, half):
        out.append(line)
    out.append('')
    left = _column('Top conversations', [(conv, human_bytes(b)) for conv, b in stats.conversations.most_common(stats.top_n)], half)
    right_rows: List[Tuple[str, str]] = [(q, str(c)) for q, c in stats.dns_queries.most_common(stats.top_n // 2)]
    right_rows += [(f'HTTP {h}', str(c)) for h, c in stats.http_hosts.most_common(stats.top_n // 2)]
    right = _column('DNS queries / HTTP hosts', right_rows, half)
    for line in _side_by_side(left, right, half):
        out.append(line)
    if stats.tcp_flags:
        out.append('')
        flags = '  '.join((f'{k}={v}' for k, v in stats.tcp_flags.most_common(6)))
        out.append(f'{BOLD}TCP flags{RESET}  {flags}')
    if stats.icmp_types:
        icmp = '  '.join((f'{k}={v}' for k, v in stats.icmp_types.most_common(6)))
        out.append(f'{BOLD}ICMP{RESET}       {icmp}')
    out.append(rule)
    out.append(f'{BOLD}Alerts{RESET} ({len(alerts)} total)')
    if not alerts:
        out.append(f'{DIM}  nothing suspicious yet{RESET}')
    else:
        for alert in alerts[-6:]:
            colour = RED if alert.severity == 'high' else YELLOW
            stamp = time.strftime('%H:%M:%S', time.localtime(alert.ts))
            line = f'  {colour}[{alert.severity.upper():<6}]{RESET} {stamp} {alert.rule}: {alert.message}'
            out.append(line[:width + 20])
    out.append(f'{DIM}Ctrl+C to stop{RESET}')
    return '\n'.join(out)

def _side_by_side(left: List[str], right: List[str], width: int) -> List[str]:
    rows = []
    for i in range(max(len(left), len(right))):
        l = left[i] if i < len(left) else ''
        r = right[i] if i < len(right) else ''
        pad = width - _visible_length(l)
        rows.append(l + ' ' * max(pad, 2) + r)
    return rows

def _visible_length(text: str) -> int:
    result = 0
    skipping = False
    for ch in text:
        if ch == '\x1b':
            skipping = True
            continue
        if skipping:
            if ch == 'm':
                skipping = False
            continue
        result += 1
    return result

def text_summary(stats: Statistics, alerts: List) -> str:
    lines = ['', '=== capture summary ===', f'packets         : {stats.packets}', f'bytes           : {stats.bytes} ({human_bytes(stats.bytes)})', f'duration        : {stats.duration:.1f}s', f'average size    : {stats.average_packet_size:.0f} B', f'filtered out    : {stats.filtered_out}', f'decode errors   : {stats.decode_errors}', '', 'protocols:']
    for name, count in stats.protocols.most_common():
        lines.append(f'  {name:<12} {count}')
    if stats.talkers:
        lines.append('')
        lines.append('top talkers:')
        for ip, size in stats.talkers.most_common(10):
            lines.append(f'  {ip:<40} {human_bytes(size)}')
    if stats.dst_ports:
        lines.append('')
        lines.append('top destination ports:')
        for port, count in stats.dst_ports.most_common(10):
            lines.append(f'  {port:<12} {count}')
    if stats.dns_queries:
        lines.append('')
        lines.append('dns queries:')
        for query, count in stats.dns_queries.most_common(10):
            lines.append(f'  {query:<50} {count}')
    lines.append('')
    lines.append(f'alerts: {len(alerts)}')
    for alert in alerts:
        stamp = time.strftime('%H:%M:%S', time.localtime(alert.ts))
        lines.append(f'  [{alert.severity.upper():<6}] {stamp} {alert.rule}: {alert.message}')
    return '\n'.join(lines)

def supports_ansi() -> bool:
    return sys.stdout.isatty()
