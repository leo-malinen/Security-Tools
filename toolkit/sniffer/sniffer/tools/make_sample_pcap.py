from __future__ import annotations
import base64
import os
import random
import struct
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from netscope.pcap import LINKTYPE_ETHERNET, PcapWriter
CLIENT_MAC = bytes.fromhex('001122334455')
ROUTER_MAC = bytes.fromhex('aabbccddeeff')
ETH_P_IP = 2048
CLIENT = '192.168.1.50'
SERVER = '93.184.216.34'
RESOLVER = '192.168.1.1'
ATTACKER = '192.168.1.66'
VICTIM = '192.168.1.10'
C2 = '203.0.113.77'
random.seed(1337)
_clock = 1700000000.0

def tick(step: float=0.004) -> float:
    global _clock
    _clock += step
    return _clock

def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += bytes(1)
    total = 0
    for i in range(0, len(data), 2):
        total += data[i] << 8 | data[i + 1]
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return ~total & 65535

def ip_to_bytes(addr: str) -> bytes:
    return bytes((int(part) for part in addr.split('.')))

def ethernet(src: bytes, dst: bytes) -> bytes:
    return struct.pack('!6s6sH', dst, src, ETH_P_IP)

def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int=64, ident: int=0) -> bytes:
    total_length = 20 + len(payload)
    header = struct.pack('!BBHHHBBH4s4s', 69, 0, total_length, ident or random.randint(1, 65535), 16384, ttl, proto, 0, ip_to_bytes(src), ip_to_bytes(dst))
    csum = checksum(header)
    header = header[:10] + struct.pack('!H', csum) + header[12:]
    return header + payload

def tcp(sport: int, dport: int, flags: int, payload: bytes=b'', seq: int=1000, ack: int=0, window: int=64240) -> bytes:
    offset_reserved = 5 << 4
    header = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, offset_reserved, flags, window, 0, 0)
    return header + payload

def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload

def icmp(icmp_type: int, code: int, ident: int, seq: int, payload: bytes) -> bytes:
    header = struct.pack('!BBHHH', icmp_type, code, 0, ident, seq)
    csum = checksum(header + payload)
    return struct.pack('!BBHHH', icmp_type, code, csum, ident, seq) + payload

def encode_dns_name(name: str) -> bytes:
    out = b''
    for label in name.split('.'):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + bytes(1)

def dns_query(ident: int, name: str, qtype: int=1) -> bytes:
    header = struct.pack('!HHHHHH', ident, 256, 1, 0, 0, 0)
    return header + encode_dns_name(name) + struct.pack('!HH', qtype, 1)

def dns_response(ident: int, name: str, address: str) -> bytes:
    header = struct.pack('!HHHHHH', ident, 33152, 1, 1, 0, 0)
    question = encode_dns_name(name) + struct.pack('!HH', 1, 1)
    answer = bytes.fromhex('c00c') + struct.pack('!HHIH', 1, 1, 300, 4) + ip_to_bytes(address)
    return header + question + answer

def frame(src_mac: bytes, dst_mac: bytes, ip_packet: bytes) -> bytes:
    return ethernet(src_mac, dst_mac) + ip_packet

def build(path: str) -> int:
    writer = PcapWriter(path, linktype=LINKTYPE_ETHERNET)
    out = writer.write
    out(tick(), frame(CLIENT_MAC, ROUTER_MAC, ipv4(CLIENT, RESOLVER, 17, udp(51820, 53, dns_query(6699, 'example.com')))))
    out(tick(0.02), frame(ROUTER_MAC, CLIENT_MAC, ipv4(RESOLVER, CLIENT, 17, udp(53, 51820, dns_response(6699, 'example.com', SERVER)))))
    out(tick(), frame(CLIENT_MAC, ROUTER_MAC, ipv4(CLIENT, SERVER, 6, tcp(44001, 80, 2, seq=1000))))
    out(tick(0.03), frame(ROUTER_MAC, CLIENT_MAC, ipv4(SERVER, CLIENT, 6, tcp(80, 44001, 18, seq=5000, ack=1001))))
    out(tick(), frame(CLIENT_MAC, ROUTER_MAC, ipv4(CLIENT, SERVER, 6, tcp(44001, 80, 16, seq=1001, ack=5001))))
    request = 'GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: netscope-demo/1.0\r\nAccept: text/html\r\n\r\n'.encode()
    out(tick(), frame(CLIENT_MAC, ROUTER_MAC, ipv4(CLIENT, SERVER, 6, tcp(44001, 80, 24, request, seq=1001, ack=5001))))
    body = b'<html><body>hello from netscope</body></html>'
    response = b'HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
    out(tick(0.05), frame(ROUTER_MAC, CLIENT_MAC, ipv4(SERVER, CLIENT, 6, tcp(80, 44001, 24, response, seq=5001, ack=1001 + len(request)))))
    out(tick(), frame(CLIENT_MAC, ROUTER_MAC, ipv4(CLIENT, SERVER, 6, tcp(44001, 80, 17, seq=1500, ack=6000))))
    out(tick(), frame(CLIENT_MAC, ROUTER_MAC, ipv4(CLIENT, '216.239.35.0', 17, udp(123, 123, bytes(48)))))
    ping_payload = bytes(range(32, 64))
    out(tick(), frame(CLIENT_MAC, ROUTER_MAC, ipv4(CLIENT, SERVER, 1, icmp(8, 0, 772, 1, ping_payload))))
    out(tick(0.04), frame(ROUTER_MAC, CLIENT_MAC, ipv4(SERVER, CLIENT, 1, icmp(0, 0, 772, 1, ping_payload))))
    creds = base64.b64encode(b'admin:hunter2').decode()
    auth_request = f'GET /admin HTTP/1.1\r\nHost: intranet.local\r\nAuthorization: Basic {creds}\r\n\r\n'.encode()
    out(tick(), frame(CLIENT_MAC, ROUTER_MAC, ipv4(CLIENT, VICTIM, 6, tcp(44010, 80, 24, auth_request, seq=200))))
    form_body = b'username=alice&password=SuperSecret123&remember=1'
    post_request = b'POST /login HTTP/1.1\r\nHost: intranet.local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ' + str(len(form_body)).encode() + b'\r\n\r\n' + form_body
    out(tick(), frame(CLIENT_MAC, ROUTER_MAC, ipv4(CLIENT, VICTIM, 6, tcp(44011, 80, 24, post_request, seq=300))))
    out(tick(), frame(CLIENT_MAC, ROUTER_MAC, ipv4(CLIENT, VICTIM, 6, tcp(44012, 21, 24, b'USER anonymous\r\n', seq=400))))
    out(tick(), frame(CLIENT_MAC, ROUTER_MAC, ipv4(CLIENT, VICTIM, 6, tcp(44012, 21, 24, b'PASS letmein\r\n', seq=420))))
    for index, port in enumerate([21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1025, 1433, 1521, 1723, 2049, 3306, 3389, 5060, 5432, 5900, 6000, 6379, 8000, 8080, 8443, 9000, 9090, 9200, 11211, 27017, 50000, 5985, 5986, 623, 1900]):
        out(tick(0.002), frame(CLIENT_MAC, ROUTER_MAC, ipv4(ATTACKER, VICTIM, 6, tcp(40000 + index, port, 2, seq=index))))
    out(tick(), frame(CLIENT_MAC, ROUTER_MAC, ipv4(ATTACKER, VICTIM, 6, tcp(41000, 80, 41))))
    out(tick(), frame(CLIENT_MAC, ROUTER_MAC, ipv4(ATTACKER, VICTIM, 6, tcp(41001, 443, 0))))
    out(tick(), frame(CLIENT_MAC, ROUTER_MAC, ipv4(ATTACKER, VICTIM, 6, tcp(41002, 22, 1))))
    for host in range(1, 30):
        out(tick(0.003), frame(CLIENT_MAC, ROUTER_MAC, ipv4(ATTACKER, f'192.168.1.{host}', 1, icmp(8, 0, 1792, host, b'sweep'))))
    for index in range(150):
        src = f'10.0.{index % 250}.{index * 7 % 250 + 1}'
        out(tick(0.001), frame(CLIENT_MAC, ROUTER_MAC, ipv4(src, VICTIM, 6, tcp(30000 + index, 80, 2, seq=index))))
    for index in range(40):
        blob = base64.b32encode(random.randbytes(32)).decode().strip('=').lower()
        name = f'{blob[:56]}.tunnel.badguy.example'
        out(tick(0.01), frame(CLIENT_MAC, ROUTER_MAC, ipv4(CLIENT, RESOLVER, 17, udp(52000 + index, 53, dns_query(16384 + index, name, qtype=16)))))
    for index in range(6):
        out(tick(0.02), frame(CLIENT_MAC, ROUTER_MAC, ipv4(CLIENT, C2, 1, icmp(8, 0, 2989, index, random.randbytes(512)))))
    out(tick(), frame(CLIENT_MAC, ROUTER_MAC, ipv4(CLIENT, C2, 6, tcp(45000, 4444, 2, seq=1))))
    out(tick(0.03), frame(ROUTER_MAC, CLIENT_MAC, ipv4(C2, CLIENT, 6, tcp(4444, 45000, 18, seq=99, ack=2))))
    out(tick(), frame(CLIENT_MAC, ROUTER_MAC, ipv4(CLIENT, C2, 6, tcp(45000, 4444, 24, b'whoami\n', seq=2, ack=100))))
    out(tick(), frame(CLIENT_MAC, ROUTER_MAC, ipv4(CLIENT, VICTIM, 6, tcp(45100, 23, 24, b'USER root\r\n', seq=10))))
    for index in range(120):
        out(tick(0.005), frame(CLIENT_MAC, ROUTER_MAC, ipv4(CLIENT, C2, 6, tcp(46000, 443, 24, random.randbytes(1400), seq=index * 1400))))
    count = writer.count
    writer.close()
    return count
if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else 'sample.pcap'
    total = build(target)
    print(f'wrote {total} packets to {target}')
