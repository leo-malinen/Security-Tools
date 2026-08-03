from __future__ import annotations

import argparse
import socket
import threading
import time
from typing import List, Tuple

CRLF = chr(13) + chr(10)

SERVICES: List[Tuple[str, int, str, bool]] = [
    ("ftp", 2121, "220 (vsFTPd 2.3.4)" + CRLF, False),
    ("ssh", 2222, "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8" + CRLF, False),
    ("http", 8081, "HTTP/1.1 200 OK" + CRLF + "Server: Apache/2.4.49 (Unix)" + CRLF + "Content-Length: 0" + CRLF + CRLF, True),
    ("smtp", 2525, "220 mail.example.local ESMTP Exim 4.89 Mon, 1 Jan 2024 00:00:00 +0000" + CRLF, False),
    ("nginx", 8082, "HTTP/1.1 200 OK" + CRLF + "Server: nginx/1.4.0" + CRLF + "Content-Length: 0" + CRLF + CRLF, True),
]


def _handle(conn: socket.socket, payload: bytes, wait_for_request: bool) -> None:
    try:
        conn.settimeout(2.0)
        if wait_for_request:
            try:
                conn.recv(2048)
            except socket.timeout:
                pass
        conn.sendall(payload)
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _serve(name: str, port: int, banner: str, wait_for_request: bool) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("127.0.0.1", port))
    except OSError as exc:
        print(f"could not bind {name} on {port}: {exc}")
        return
    server.listen(16)
    print(f"{name:<8} listening on 127.0.0.1:{port}")
    while True:
        try:
            conn, _ = server.accept()
        except OSError:
            break
        threading.Thread(target=_handle, args=(conn, banner.encode(), wait_for_request), daemon=True).start()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run fake vulnerable services on localhost for testing vulnscan.")
    parser.parse_args()
    for name, port, banner, wait in SERVICES:
        threading.Thread(target=_serve, args=(name, port, banner, wait), daemon=True).start()
    ports = ",".join(str(item[1]) for item in SERVICES)
    print(f"try: python3 -m vulnscan 127.0.0.1 -Pn -p {ports} -o mock-report")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
