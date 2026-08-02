from __future__ import annotations
import struct
from typing import List, Optional, Tuple
from ..models import ICMPHeader, TCPHeader, UDPHeader
TCP_OPTION_NAMES = {0: 'eol', 1: 'nop', 2: 'mss', 3: 'wscale', 4: 'sack-permitted', 5: 'sack', 8: 'timestamps', 28: 'user-timeout', 29: 'authentication', 34: 'fast-open'}

def _parse_tcp_options(data: bytes) -> List[str]:
    options: List[str] = []
    i = 0
    while i < len(data):
        kind = data[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= len(data):
            break
        length = data[i + 1]
        if length < 2 or i + length > len(data):
            break
        body = data[i + 2:i + length]
        name = TCP_OPTION_NAMES.get(kind, f'opt-{kind}')
        if kind == 2 and len(body) == 2:
            options.append(f"mss={struct.unpack('!H', body)[0]}")
        elif kind == 3 and len(body) == 1:
            options.append(f'wscale={body[0]}')
        elif kind == 8 and len(body) == 8:
            tsval, tsecr = struct.unpack('!II', body)
            options.append(f'ts={tsval}/{tsecr}')
        else:
            options.append(name)
        i += length
    return options

def parse_tcp(data: bytes) -> Tuple[Optional[TCPHeader], bytes]:
    if len(data) < 20:
        return (None, b'')
    sport, dport, seq, ack, offset_reserved, flags, window, checksum, urgent = struct.unpack('!HHIIBBHHH', data[:20])
    header_length = (offset_reserved >> 4) * 4
    if header_length < 20 or header_length > len(data):
        header_length = 20
    options = _parse_tcp_options(data[20:header_length]) if header_length > 20 else []
    payload = data[header_length:]
    header = TCPHeader(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, window=window, header_length=header_length, checksum=checksum, urgent=urgent, options=options, payload_length=len(payload))
    return (header, payload)

def parse_udp(data: bytes) -> Tuple[Optional[UDPHeader], bytes]:
    if len(data) < 8:
        return (None, b'')
    sport, dport, length, checksum = struct.unpack('!HHHH', data[:8])
    declared = length - 8 if length >= 8 else 0
    payload = data[8:8 + declared] if declared and 8 + declared <= len(data) else data[8:]
    header = UDPHeader(sport=sport, dport=dport, length=length, checksum=checksum, payload_length=len(payload))
    return (header, payload)

def parse_icmp(data: bytes) -> Tuple[Optional[ICMPHeader], bytes]:
    if len(data) < 4:
        return (None, b'')
    icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
    ident = seq = None
    payload = data[4:]
    if icmp_type in (0, 8, 13, 14, 128, 129) and len(data) >= 8:
        ident, seq = struct.unpack('!HH', data[4:8])
        payload = data[8:]
    header = ICMPHeader(type=icmp_type, code=code, checksum=checksum, ident=ident, seq=seq, payload_length=len(payload))
    return (header, payload)
