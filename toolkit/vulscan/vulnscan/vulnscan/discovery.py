from __future__ import annotations

import ipaddress
import socket
from typing import Iterable, List, Optional

from .services import TOP_PORTS

DEFAULT_PING_PORTS = [80, 443, 22, 445, 3389, 21, 25, 53, 139, 8080]


def _tokens(spec) -> List[str]:
    if isinstance(spec, (list, tuple)):
        raw: List[str] = []
        for item in spec:
            raw.extend(str(item).replace(",", " ").split())
        return raw
    return str(spec).replace(",", " ").split()


def expand_targets(spec) -> List[str]:
    targets: List[str] = []
    for token in _tokens(spec):
        targets.extend(_expand_one(token))
    seen = set()
    ordered: List[str] = []
    for target in targets:
        if target not in seen:
            seen.add(target)
            ordered.append(target)
    return ordered


def _expand_one(token: str) -> List[str]:
    if "/" in token:
        network = ipaddress.ip_network(token, strict=False)
        hosts = [str(ip) for ip in network.hosts()]
        return hosts or [str(network.network_address)]
    if "-" in token and _looks_like_range(token):
        return _expand_range(token)
    return [token]


def _looks_like_range(token: str) -> bool:
    head = token.split("-", 1)[0]
    return head.count(".") == 3 and all(part.isdigit() for part in head.split("."))


def _expand_range(token: str) -> List[str]:
    left, right = token.split("-", 1)
    if "." in right:
        start = int(ipaddress.ip_address(left))
        end = int(ipaddress.ip_address(right))
    else:
        base, last = left.rsplit(".", 1)
        start = int(ipaddress.ip_address(left))
        end = int(ipaddress.ip_address(f"{base}.{int(right)}"))
    if end < start:
        start, end = end, start
    return [str(ipaddress.ip_address(value)) for value in range(start, end + 1)]


def parse_ports(spec) -> List[int]:
    if spec is None:
        return list(TOP_PORTS)
    ports = set()
    for part in str(spec).replace(",", " ").split():
        if "-" in part:
            low, high = part.split("-", 1)
            ports.update(range(int(low), int(high) + 1))
        else:
            ports.add(int(part))
    return sorted(port for port in ports if 0 < port < 65536)


def resolve(host: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(host)[0]
    except OSError:
        return None


def host_is_up(host: str, ports: Optional[Iterable[int]] = None, timeout: float = 1.0) -> bool:
    for port in list(ports or DEFAULT_PING_PORTS):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((host, port)) == 0:
                    return True
        except OSError:
            continue
    return False
