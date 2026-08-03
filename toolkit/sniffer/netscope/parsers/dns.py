from __future__ import annotations
import socket
import struct
from typing import Optional, Tuple
from ..models import DNSMessage, DNSQuestion, DNSRecord
DNS_PORTS = {53, 5353, 5355, 853}
MAX_POINTER_DEPTH = 8

def _read_name(data: bytes, offset: int, depth: int=0) -> Tuple[str, int]:
    labels = []
    while True:
        if offset >= len(data):
            raise ValueError('name runs past end of message')
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 192 == 192:
            if offset + 1 >= len(data):
                raise ValueError('truncated compression pointer')
            pointer = (length & 63) << 8 | data[offset + 1]
            offset += 2
            if depth < MAX_POINTER_DEPTH:
                suffix, _ = _read_name(data, pointer, depth + 1)
                if suffix:
                    labels.append(suffix)
            break
        if length & 192:
            raise ValueError('unsupported label type')
        offset += 1
        if offset + length > len(data):
            raise ValueError('truncated label')
        labels.append(data[offset:offset + length].decode('utf-8', 'replace'))
        offset += length
    return ('.'.join((label for label in labels if label)), offset)

def _decode_rdata(data: bytes, rtype: int, rdata: bytes, rdata_offset: int) -> str:
    try:
        if rtype == 1 and len(rdata) == 4:
            return socket.inet_ntop(socket.AF_INET, rdata)
        if rtype == 28 and len(rdata) == 16:
            return socket.inet_ntop(socket.AF_INET6, rdata)
        if rtype in (2, 5, 12):
            name, _ = _read_name(data, rdata_offset)
            return name
        if rtype == 15 and len(rdata) > 2:
            pref = struct.unpack('!H', rdata[:2])[0]
            name, _ = _read_name(data, rdata_offset + 2)
            return f'{pref} {name}'
        if rtype == 16:
            chunks = []
            i = 0
            while i < len(rdata):
                size = rdata[i]
                chunks.append(rdata[i + 1:i + 1 + size].decode('utf-8', 'replace'))
                i += 1 + size
            return ' '.join(chunks)
        if rtype == 6:
            name, _ = _read_name(data, rdata_offset)
            return f'soa {name}'
        if rtype == 33 and len(rdata) >= 6:
            _prio, _weight, port = struct.unpack('!HHH', rdata[:6])
            name, _ = _read_name(data, rdata_offset + 6)
            return f'{name}:{port}'
    except (ValueError, struct.error, OSError):
        pass
    return rdata[:48].hex()

def looks_like_dns(sport: Optional[int], dport: Optional[int]) -> bool:
    return bool(sport in DNS_PORTS or dport in DNS_PORTS)

def parse_dns(data: bytes) -> Optional[DNSMessage]:
    if len(data) < 12:
        return None
    try:
        ident, flags, qdcount, ancount, _nscount, _arcount = struct.unpack('!HHHHHH', data[:12])
    except struct.error:
        return None
    if qdcount > 64 or ancount > 128:
        return None
    message = DNSMessage(ident=ident, is_response=bool(flags & 32768), opcode=flags >> 11 & 15, rcode=flags & 15, truncated=bool(flags & 512), recursion_desired=bool(flags & 256))
    offset = 12
    try:
        for _ in range(qdcount):
            name, offset = _read_name(data, offset)
            if offset + 4 > len(data):
                return message
            qtype, qclass = struct.unpack('!HH', data[offset:offset + 4])
            offset += 4
            message.questions.append(DNSQuestion(name=name, qtype=qtype, qclass=qclass))
        for _ in range(ancount):
            name, offset = _read_name(data, offset)
            if offset + 10 > len(data):
                return message
            rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlength]
            if len(rdata) < rdlength:
                return message
            message.answers.append(DNSRecord(name=name, rtype=rtype, rclass=rclass, ttl=ttl, data=_decode_rdata(data, rtype, rdata, offset)))
            offset += rdlength
    except (ValueError, struct.error):
        return message
    return message
