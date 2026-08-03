from __future__ import annotations
import ipaddress
import math
from collections import Counter

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total * math.log2(c / total) for c in counts.values()))

def label_entropy(text: str) -> float:
    return shannon_entropy(text.encode('utf-8', 'replace'))

def human_bytes(n: float) -> str:
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if abs(n) < 1024.0:
            return f'{n:.0f}{unit}' if unit == 'B' else f'{n:.1f}{unit}'
        n /= 1024.0
    return f'{n:.1f}PB'

def human_rate(bytes_per_sec: float) -> str:
    return human_bytes(bytes_per_sec) + '/s'
_INTERNAL_NETWORKS = tuple((ipaddress.ip_network(cidr) for cidr in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '169.254.0.0/16', '127.0.0.0/8', 'fc00::/7', 'fe80::/10', '::1/128')))

def is_private_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.is_multicast:
        return True
    return any((ip in network for network in _INTERNAL_NETWORKS if ip.version == network.version))

def in_network(addr: str, network: str) -> bool:
    try:
        return ipaddress.ip_address(addr) in ipaddress.ip_network(network, strict=False)
    except ValueError:
        return False

def base_domain(name: str, levels: int=2) -> str:
    parts = [p for p in name.strip('.').split('.') if p]
    if len(parts) <= levels:
        return '.'.join(parts)
    return '.'.join(parts[-levels:])

def hexdump(data: bytes, width: int=16, limit: int=256) -> str:
    lines = []
    view = data[:limit]
    for offset in range(0, len(view), width):
        chunk = view[offset:offset + width]
        hexpart = ' '.join((f'{b:02x}' for b in chunk))
        asciipart = ''.join((chr(b) if 32 <= b < 127 else '.' for b in chunk))
        lines.append(f'  {offset:04x}  {hexpart:<{width * 3}} {asciipart}')
    if len(data) > limit:
        lines.append(f'  ... {len(data) - limit} more bytes')
    return '\n'.join(lines)

def printable_preview(data: bytes, limit: int=200) -> str:
    text = data[:limit].decode('utf-8', 'replace')
    return ''.join((ch if ch.isprintable() or ch in ' \t' else '.' for ch in text))
