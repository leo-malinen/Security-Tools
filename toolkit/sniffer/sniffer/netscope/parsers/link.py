from __future__ import annotations
import socket
import struct
from typing import Optional, Tuple
from ..models import ARP, Ethernet
ETH_P_IP = 2048
ETH_P_IPV6 = 34525
ETH_P_ARP = 2054
VLAN_TAGS = (33024, 34984, 37120)

def format_mac(raw: bytes) -> str:
    return ':'.join((f'{b:02x}' for b in raw))

def parse_ethernet(data: bytes) -> Tuple[Optional[Ethernet], bytes]:
    if len(data) < 14:
        return (None, b'')
    dst, src, ethertype = struct.unpack('!6s6sH', data[:14])
    offset = 14
    vlan: Optional[int] = None
    while ethertype in VLAN_TAGS and len(data) >= offset + 4:
        tci, ethertype = struct.unpack('!HH', data[offset:offset + 4])
        if vlan is None:
            vlan = tci & 4095
        offset += 4
    return (Ethernet(src=format_mac(src), dst=format_mac(dst), ethertype=ethertype, vlan=vlan), data[offset:])

def parse_linux_sll(data: bytes) -> Tuple[Optional[Ethernet], bytes]:
    if len(data) < 16:
        return (None, b'')
    _pkttype, _hatype, halen, addr, ethertype = struct.unpack('!HHH8sH', data[:16])
    src = format_mac(addr[:min(halen, 8)]) if halen else '00:00:00:00:00:00'
    return (Ethernet(src=src, dst='00:00:00:00:00:00', ethertype=ethertype), data[16:])

def parse_null(data: bytes) -> Tuple[Optional[Ethernet], bytes]:
    if len(data) < 4:
        return (None, b'')
    family = struct.unpack('<I', data[:4])[0]
    ethertype = ETH_P_IPV6 if family in (24, 28, 30) else ETH_P_IP
    return (Ethernet(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', ethertype=ethertype), data[4:])

def parse_arp(data: bytes) -> Optional[ARP]:
    if len(data) < 28:
        return None
    _htype, _ptype, hlen, plen, opcode = struct.unpack('!HHBBH', data[:8])
    if hlen != 6 or plen != 4 or len(data) < 28:
        return None
    sender_mac, sender_ip, target_mac, target_ip = struct.unpack('!6s4s6s4s', data[8:28])
    return ARP(opcode=opcode, sender_mac=format_mac(sender_mac), sender_ip=socket.inet_ntop(socket.AF_INET, sender_ip), target_mac=format_mac(target_mac), target_ip=socket.inet_ntop(socket.AF_INET, target_ip))
