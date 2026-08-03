from __future__ import annotations

import socket
import ssl
from typing import Dict, Optional

CRLF = chr(13) + chr(10)
HTTP_PROBE = ("HEAD / HTTP/1.0" + CRLF + "Host: scan" + CRLF + CRLF).encode()
EHLO_PROBE = ("EHLO scanner.local" + CRLF).encode()

HTTP_PORTS = {80, 8000, 8080, 8888, 443, 8443}
TLS_PORTS = {443, 8443, 993, 995, 465, 636}
SPEAKS_FIRST = {21, 22, 23, 25, 110, 143, 587, 3306, 5432, 6667}

PROBES: Dict[int, bytes] = {
    80: HTTP_PROBE,
    8000: HTTP_PROBE,
    8080: HTTP_PROBE,
    8888: HTTP_PROBE,
    443: HTTP_PROBE,
    8443: HTTP_PROBE,
    25: EHLO_PROBE,
    587: EHLO_PROBE,
    6379: ("INFO" + CRLF).encode(),
    11211: ("version" + CRLF).encode(),
}


def _tls_wrap(sock: socket.socket, host: str) -> Optional[ssl.SSLSocket]:
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context.wrap_socket(sock, server_hostname=host)
    except (ssl.SSLError, OSError, ValueError):
        return None


def grab_banner(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None

    active = raw
    try:
        if port in TLS_PORTS:
            wrapped = _tls_wrap(raw, host)
            if wrapped is None:
                return None
            active = wrapped
        active.settimeout(timeout)

        probe = PROBES.get(port)
        if probe is None and port in HTTP_PORTS:
            probe = HTTP_PROBE

        if probe and port not in SPEAKS_FIRST:
            try:
                active.sendall(probe)
            except OSError:
                pass

        data = b""
        try:
            data = active.recv(4096)
        except (socket.timeout, ssl.SSLError):
            data = b""

        if not data:
            fallback = probe or HTTP_PROBE
            try:
                active.sendall(fallback)
                data = active.recv(4096)
            except (OSError, ssl.SSLError):
                data = b""
    finally:
        try:
            active.close()
        except OSError:
            pass

    text = data.decode("latin-1", "replace").strip()
    return text or None
