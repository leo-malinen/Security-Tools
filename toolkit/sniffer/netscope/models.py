from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
IP_PROTO_NAMES = {1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 41: 'IPv6', 47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPv6', 89: 'OSPF', 132: 'SCTP'}
TCP_FLAG_BITS = [(1, 'FIN'), (2, 'SYN'), (4, 'RST'), (8, 'PSH'), (16, 'ACK'), (32, 'URG'), (64, 'ECE'), (128, 'CWR')]

@dataclass
class Ethernet:
    src: str
    dst: str
    ethertype: int
    vlan: Optional[int] = None

@dataclass
class ARP:
    opcode: int
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str

    @property
    def op_name(self) -> str:
        return {1: 'request', 2: 'reply'}.get(self.opcode, str(self.opcode))

@dataclass
class IPHeader:
    version: int
    src: str
    dst: str
    proto: int
    ttl: int
    total_length: int
    header_length: int = 20
    ident: int = 0
    flags: int = 0
    frag_offset: int = 0
    tos: int = 0

    @property
    def proto_name(self) -> str:
        return IP_PROTO_NAMES.get(self.proto, f'IP-{self.proto}')

    @property
    def dont_fragment(self) -> bool:
        return bool(self.flags & 2)

    @property
    def more_fragments(self) -> bool:
        return bool(self.flags & 1)

@dataclass
class TCPHeader:
    sport: int
    dport: int
    seq: int
    ack: int
    flags: int
    window: int
    header_length: int
    checksum: int = 0
    urgent: int = 0
    options: List[str] = field(default_factory=list)
    payload_length: int = 0

    @property
    def flag_names(self) -> List[str]:
        return [name for bit, name in TCP_FLAG_BITS if self.flags & bit]

    @property
    def flag_string(self) -> str:
        return '|'.join(self.flag_names) or 'NONE'

    def has(self, name: str) -> bool:
        for bit, flag in TCP_FLAG_BITS:
            if flag == name.upper():
                return bool(self.flags & bit)
        return False

    @property
    def is_syn_only(self) -> bool:
        return self.flags == 2

    @property
    def scan_signature(self) -> Optional[str]:
        flags = self.flags & 63
        if flags == 0:
            return 'NULL scan'
        if flags == 1:
            return 'FIN scan'
        if flags == 41:
            return 'XMAS scan'
        if flags & 3 == 3:
            return 'SYN+FIN scan'
        if flags == 32 or flags == 33:
            return 'URG probe'
        return None

@dataclass
class UDPHeader:
    sport: int
    dport: int
    length: int
    checksum: int = 0
    payload_length: int = 0

@dataclass
class ICMPHeader:
    type: int
    code: int
    checksum: int = 0
    ident: Optional[int] = None
    seq: Optional[int] = None
    payload_length: int = 0

    @property
    def type_name(self) -> str:
        names = {0: 'echo-reply', 3: 'dest-unreachable', 4: 'source-quench', 5: 'redirect', 8: 'echo-request', 9: 'router-advertisement', 10: 'router-solicitation', 11: 'time-exceeded', 12: 'parameter-problem', 13: 'timestamp', 14: 'timestamp-reply', 128: 'echo-request-v6', 129: 'echo-reply-v6'}
        return names.get(self.type, f'type-{self.type}')

@dataclass
class DNSQuestion:
    name: str
    qtype: int
    qclass: int

    @property
    def type_name(self) -> str:
        return DNS_TYPES.get(self.qtype, str(self.qtype))

@dataclass
class DNSRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    data: str

    @property
    def type_name(self) -> str:
        return DNS_TYPES.get(self.rtype, str(self.rtype))
DNS_TYPES = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 10: 'NULL', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 35: 'NAPTR', 41: 'OPT', 43: 'DS', 48: 'DNSKEY', 252: 'AXFR', 255: 'ANY'}
DNS_RCODES = {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED'}

@dataclass
class DNSMessage:
    ident: int
    is_response: bool
    opcode: int
    rcode: int
    truncated: bool
    recursion_desired: bool
    questions: List[DNSQuestion] = field(default_factory=list)
    answers: List[DNSRecord] = field(default_factory=list)

    @property
    def rcode_name(self) -> str:
        return DNS_RCODES.get(self.rcode, str(self.rcode))

    def summary(self) -> str:
        kind = 'response' if self.is_response else 'query'
        q = self.questions[0].name if self.questions else '?'
        qtype = self.questions[0].type_name if self.questions else '?'
        extra = ''
        if self.is_response:
            answers = ','.join((a.data for a in self.answers[:3])) or self.rcode_name
            extra = f' -> {answers}'
        return f'DNS {kind} {qtype} {q}{extra}'

@dataclass
class HTTPMessage:
    kind: str
    method: Optional[str] = None
    path: Optional[str] = None
    version: Optional[str] = None
    status: Optional[int] = None
    reason: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    body_preview: str = ''
    body_length: int = 0

    @property
    def host(self) -> Optional[str]:
        return self.headers.get('host')

    @property
    def user_agent(self) -> Optional[str]:
        return self.headers.get('user-agent')

    def summary(self) -> str:
        if self.kind == 'request':
            host = self.host or ''
            return f'HTTP {self.method} {host}{self.path}'
        return f"HTTP {self.status} {self.reason or ''}".strip()

@dataclass
class Packet:
    ts: float
    raw: bytes
    wire_length: int
    eth: Optional[Ethernet] = None
    arp: Optional[ARP] = None
    ip: Optional[IPHeader] = None
    tcp: Optional[TCPHeader] = None
    udp: Optional[UDPHeader] = None
    icmp: Optional[ICMPHeader] = None
    dns: Optional[DNSMessage] = None
    http: Optional[HTTPMessage] = None
    payload: bytes = b''
    errors: List[str] = field(default_factory=list)

    @property
    def captured_length(self) -> int:
        return len(self.raw)

    @property
    def protocol(self) -> str:
        if self.dns:
            return 'DNS'
        if self.http:
            return 'HTTP'
        if self.tcp:
            return 'TCP'
        if self.udp:
            return 'UDP'
        if self.icmp:
            return 'ICMP'
        if self.arp:
            return 'ARP'
        if self.ip:
            return self.ip.proto_name
        if self.eth:
            return f'ETH-0x{self.eth.ethertype:04x}'
        return 'UNKNOWN'

    @property
    def transport_protocol(self) -> Optional[str]:
        if self.tcp:
            return 'TCP'
        if self.udp:
            return 'UDP'
        if self.icmp:
            return 'ICMP'
        return None

    @property
    def src_ip(self) -> Optional[str]:
        if self.ip:
            return self.ip.src
        if self.arp:
            return self.arp.sender_ip
        return None

    @property
    def dst_ip(self) -> Optional[str]:
        if self.ip:
            return self.ip.dst
        if self.arp:
            return self.arp.target_ip
        return None

    @property
    def sport(self) -> Optional[int]:
        if self.tcp:
            return self.tcp.sport
        if self.udp:
            return self.udp.sport
        return None

    @property
    def dport(self) -> Optional[int]:
        if self.tcp:
            return self.tcp.dport
        if self.udp:
            return self.udp.dport
        return None

    def endpoints(self) -> Tuple[str, str]:
        src = self.src_ip or (self.eth.src if self.eth else '?')
        dst = self.dst_ip or (self.eth.dst if self.eth else '?')
        if self.sport is not None:
            src = f'{src}:{self.sport}'
        if self.dport is not None:
            dst = f'{dst}:{self.dport}'
        return (src, dst)

    def summary(self) -> str:
        src, dst = self.endpoints()
        base = f'{src} > {dst}'
        if self.http:
            return f'{base} {self.http.summary()}'
        if self.dns:
            return f'{base} {self.dns.summary()}'
        if self.tcp:
            return f'{base} TCP [{self.tcp.flag_string}] seq={self.tcp.seq} win={self.tcp.window} len={self.tcp.payload_length}'
        if self.udp:
            return f'{base} UDP len={self.udp.payload_length}'
        if self.icmp:
            return f'{base} ICMP {self.icmp.type_name} id={self.icmp.ident} len={self.icmp.payload_length}'
        if self.arp:
            return f'ARP {self.arp.op_name} {self.arp.sender_ip} -> {self.arp.target_ip}'
        return f'{base} {self.protocol} len={self.wire_length}'

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {'ts': self.ts, 'protocol': self.protocol, 'length': self.wire_length, 'src': self.src_ip, 'dst': self.dst_ip, 'sport': self.sport, 'dport': self.dport}
        if self.tcp:
            out['tcp_flags'] = self.tcp.flag_string
        if self.dns:
            out['dns'] = self.dns.summary()
        if self.http:
            out['http'] = self.http.summary()
        return out
