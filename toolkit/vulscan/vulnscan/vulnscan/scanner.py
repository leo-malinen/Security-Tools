from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Optional

from .models import PortResult


def _probe(host: str, port: int, timeout: float):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return port, sock.connect_ex((host, port)) == 0
    except OSError:
        return port, False


def scan_ports(
    host: str,
    ports: List[int],
    timeout: float = 1.0,
    workers: int = 200,
    progress: Optional[Callable[[int, int], None]] = None,
) -> List[PortResult]:
    ports = list(ports)
    if not ports:
        return []
    open_ports: List[PortResult] = []
    total = len(ports)
    completed = 0
    with ThreadPoolExecutor(max_workers=max(1, min(workers, total))) as pool:
        futures = {pool.submit(_probe, host, port, timeout): port for port in ports}
        for future in as_completed(futures):
            port, is_open = future.result()
            completed += 1
            if progress is not None:
                progress(completed, total)
            if is_open:
                open_ports.append(PortResult(port=port, state="open"))
    open_ports.sort(key=lambda result: result.port)
    return open_ports
