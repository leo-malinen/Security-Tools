from __future__ import annotations
from typing import Optional
from .models import Packet
from .pcap import LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, LINKTYPE_NULL, LINKTYPE_RAW
from .parsers import ETH_P_ARP, ETH_P_IP, ETH_P_IPV6, looks_like_dns, looks_like_http, parse_arp, parse_dns, parse_ethernet, parse_http, parse_icmp, parse_ipv4, parse_ipv6, parse_linux_sll, parse_null, parse_tcp, parse_udp
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1
PROTO_ICMPV6 = 58

def decode(data: bytes, ts: float, linktype: int=LINKTYPE_ETHERNET, wire_length: Optional[int]=None) -> Packet:
    packet = Packet(ts=ts, raw=data, wire_length=wire_length if wire_length is not None else len(data))
    try:
        payload = _decode_link(packet, data, linktype)
        if payload is None:
            return packet
        payload = _decode_network(packet, payload)
        if payload is None:
            return packet
        _decode_transport(packet, payload)
        _decode_application(packet)
    except Exception as exc:
        packet.errors.append(f'{type(exc).__name__}: {exc}')
    return packet

def _decode_link(packet: Packet, data: bytes, linktype: int) -> Optional[bytes]:
    if linktype == LINKTYPE_RAW:
        return data
    if linktype == LINKTYPE_ETHERNET:
        eth, rest = parse_ethernet(data)
    elif linktype == LINKTYPE_LINUX_SLL:
        eth, rest = parse_linux_sll(data)
    elif linktype == LINKTYPE_NULL:
        eth, rest = parse_null(data)
    else:
        packet.errors.append(f'unsupported linktype {linktype}')
        return None
    if eth is None:
        packet.errors.append('truncated link header')
        return None
    packet.eth = eth
    if eth.ethertype == ETH_P_ARP:
        packet.arp = parse_arp(rest)
        return None
    if eth.ethertype not in (ETH_P_IP, ETH_P_IPV6):
        packet.payload = rest
        return None
    return rest

def _decode_network(packet: Packet, payload: bytes) -> Optional[bytes]:
    if not payload:
        return None
    version = payload[0] >> 4
    if version == 4:
        header, rest = parse_ipv4(payload)
    elif version == 6:
        header, rest = parse_ipv6(payload)
    else:
        packet.payload = payload
        return None
    if header is None:
        packet.errors.append('truncated IP header')
        return None
    packet.ip = header
    if header.version == 4 and header.frag_offset > 0:
        packet.payload = rest
        packet.errors.append('non-initial fragment')
        return None
    return rest

def _decode_transport(packet: Packet, payload: bytes) -> None:
    assert packet.ip is not None
    proto = packet.ip.proto
    if proto == PROTO_TCP:
        header, body = parse_tcp(payload)
        if header is None:
            packet.errors.append('truncated TCP header')
            packet.payload = payload
            return
        packet.tcp = header
        packet.payload = body
    elif proto == PROTO_UDP:
        header, body = parse_udp(payload)
        if header is None:
            packet.errors.append('truncated UDP header')
            packet.payload = payload
            return
        packet.udp = header
        packet.payload = body
    elif proto in (PROTO_ICMP, PROTO_ICMPV6):
        header, body = parse_icmp(payload)
        if header is None:
            packet.errors.append('truncated ICMP header')
            packet.payload = payload
            return
        packet.icmp = header
        packet.payload = body
    else:
        packet.payload = payload

def _decode_application(packet: Packet) -> None:
    payload = packet.payload
    if not payload:
        return
    if looks_like_dns(packet.sport, packet.dport):
        candidate = payload[2:] if packet.tcp and len(payload) > 2 else payload
        packet.dns = parse_dns(candidate)
        if packet.dns is not None:
            return
    if packet.tcp and looks_like_http(payload):
        packet.http = parse_http(payload)
