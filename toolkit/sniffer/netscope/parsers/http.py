from __future__ import annotations
from typing import Optional
from ..models import HTTPMessage
CRLF = bytes.fromhex('0d0a')
HEADER_END = bytes.fromhex('0d0a0d0a')
LF_HEADER_END = bytes.fromhex('0a0a')
HTTP_METHODS = (b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS', b'PATCH', b'TRACE', b'CONNECT')
COMMON_HTTP_PORTS = {80, 81, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000}
BODY_PREVIEW_LIMIT = 512

def looks_like_http(payload: bytes) -> bool:
    if len(payload) < 16:
        return False
    if payload.startswith(b'HTTP/'):
        return True
    return any((payload.startswith(method + b' ') for method in HTTP_METHODS))

def _split_head(payload: bytes) -> tuple[bytes, bytes]:
    idx = payload.find(HEADER_END)
    if idx >= 0:
        return (payload[:idx], payload[idx + 4:])
    idx = payload.find(LF_HEADER_END)
    if idx >= 0:
        return (payload[:idx], payload[idx + 2:])
    return (payload, b'')

def parse_http(payload: bytes) -> Optional[HTTPMessage]:
    if not looks_like_http(payload):
        return None
    head, body = _split_head(payload)
    lines = head.replace(CRLF, b'\n').split(b'\n')
    if not lines:
        return None
    start_line = lines[0].decode('latin-1', 'replace').strip()
    message: Optional[HTTPMessage] = None
    if start_line.startswith('HTTP/'):
        parts = start_line.split(' ', 2)
        try:
            status = int(parts[1]) if len(parts) > 1 else None
        except ValueError:
            status = None
        message = HTTPMessage(kind='response', version=parts[0], status=status, reason=parts[2] if len(parts) > 2 else None)
    else:
        parts = start_line.split(' ')
        if len(parts) < 2:
            return None
        message = HTTPMessage(kind='request', method=parts[0], path=parts[1], version=parts[2] if len(parts) > 2 else 'HTTP/1.0')
    for line in lines[1:]:
        if not line.strip():
            continue
        decoded = line.decode('latin-1', 'replace')
        if ':' not in decoded:
            continue
        name, _, value = decoded.partition(':')
        message.headers[name.strip().lower()] = value.strip()
    message.body_length = len(body)
    if body:
        text = body[:BODY_PREVIEW_LIMIT].decode('latin-1', 'replace')
        message.body_preview = ''.join((ch if ch.isprintable() else '.' for ch in text))
    return message
