from __future__ import annotations
import socket
import struct
from typing import Optional, Tuple
from ..models import IPHeader
EXTENSION_HEADERS = {0, 43, 44, 60}

def parse_ipv4(data: bytes) -> Tuple[Optional[IPHeader], bytes]:
    if len(data) < 20:
        return (None, b'')
    ver_ihl = data[0]
    version = ver_ihl >> 4
    ihl = (ver_ihl & 15) * 4
    if version != 4 or ihl < 20 or len(data) < ihl:
        return (None, b'')
    tos, total_length, ident, flags_frag, ttl, proto = struct.unpack('!BHHHBB', data[1:10])
    src = socket.inet_ntop(socket.AF_INET, data[12:16])
    dst = socket.inet_ntop(socket.AF_INET, data[16:20])
    header = IPHeader(version=4, src=src, dst=dst, proto=proto, ttl=ttl, total_length=total_length, header_length=ihl, ident=ident, flags=flags_frag >> 13, frag_offset=(flags_frag & 8191) * 8, tos=tos)
    end = total_length if 0 < total_length <= len(data) else len(data)
    return (header, data[ihl:end])

def parse_ipv6(data: bytes) -> Tuple[Optional[IPHeader], bytes]:
    if len(data) < 40:
        return (None, b'')
    first_word, payload_length, next_header, hop_limit = struct.unpack('!IHBB', data[:8])
    if first_word >> 28 != 6:
        return (None, b'')
    src = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
    offset = 40
    proto = next_header
    while proto in EXTENSION_HEADERS and len(data) >= offset + 8:
        proto = data[offset]
        ext_len = 8 if data[offset + 1] == 0 else (data[offset + 1] + 1) * 8
        if proto == 44:
            ext_len = 8
        offset += ext_len
    header = IPHeader(version=6, src=src, dst=dst, proto=proto, ttl=hop_limit, total_length=payload_length + 40, header_length=offset)
    return (header, data[offset:])
