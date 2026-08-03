from __future__ import annotations
import os
import platform
import socket
import struct
import sys
import time
from typing import Iterator, List, Optional, Tuple
from .pcap import LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, LINKTYPE_RAW, PcapReader
Frame = Tuple[float, bytes, int]
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
ETH_P_ALL = 3
SIO_RCVALL = 2550136833
RCVALL_ON = 1

class CaptureError(RuntimeError):
    pass

class PacketSource:
    name: str = 'unknown'
    linktype: int = LINKTYPE_ETHERNET
    live: bool = True

    def frames(self) -> Iterator[Optional[Frame]]:
        raise NotImplementedError

    def close(self) -> None:
        pass

    def __enter__(self) -> 'PacketSource':
        return self

    def __exit__(self, *exc) -> None:
        self.close()

class PcapFileSource(PacketSource):
    live = False

    def __init__(self, path: str, realtime: bool=False):
        self._reader = PcapReader(path)
        self.linktype = self._reader.linktype
        self.name = f'file:{os.path.basename(path)}'
        self.realtime = realtime

    def frames(self) -> Iterator[Frame]:
        previous: Optional[float] = None
        for ts, data, wirelen in self._reader:
            if self.realtime and previous is not None:
                delay = ts - previous
                if 0 < delay < 5:
                    time.sleep(delay)
            previous = ts
            yield (ts, data, wirelen)

    def close(self) -> None:
        self._reader.close()

class LinuxRawSource(PacketSource):

    def __init__(self, interface: Optional[str]=None, snaplen: int=65535, promiscuous: bool=True):
        if not hasattr(socket, 'AF_PACKET'):
            raise CaptureError('AF_PACKET is only available on Linux')
        self.snaplen = snaplen
        try:
            self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
        except PermissionError as exc:
            raise CaptureError('permission denied opening a raw socket - run with sudo, or grant the capability once: sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))') from exc
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        if interface:
            self._sock.bind((interface, 0))
            if promiscuous:
                self._enable_promiscuous(interface)
        self._sock.settimeout(0.5)
        self.name = f"linux:{interface or 'any'}"
        self.linktype = LINKTYPE_ETHERNET

    def _enable_promiscuous(self, interface: str) -> None:
        try:
            index = socket.if_nametoindex(interface)
            request = struct.pack('IHH8s', index, PACKET_MR_PROMISC, 0, b'')
            self._sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, request)
        except OSError:
            pass

    def frames(self) -> Iterator[Frame]:
        while True:
            try:
                data = self._sock.recv(self.snaplen)
            except socket.timeout:
                yield None
                continue
            except OSError as exc:
                raise CaptureError(f'capture read failed: {exc}') from exc
            if data:
                yield (time.time(), data, len(data))

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass

class WindowsRawSource(PacketSource):

    def __init__(self, address: Optional[str]=None, snaplen: int=65535):
        self.snaplen = snaplen
        host = address or self._default_address()
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self._sock.bind((host, 0))
            self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self._sock.ioctl(SIO_RCVALL, RCVALL_ON)
        except (PermissionError, OSError) as exc:
            raise CaptureError(f'could not open a raw socket on {host}: {exc}. Run PowerShell as Administrator, or install Npcap and pass --backend scapy.') from exc
        self._sock.settimeout(0.5)
        self.name = f'windows:{host}'
        self.linktype = LINKTYPE_RAW

    @staticmethod
    def _default_address() -> str:
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.connect(('8.8.8.8', 80))
            addr = probe.getsockname()[0]
            probe.close()
            return addr
        except OSError:
            return socket.gethostbyname(socket.gethostname())

    def frames(self) -> Iterator[Frame]:
        while True:
            try:
                data = self._sock.recv(self.snaplen)
            except socket.timeout:
                yield None
                continue
            except OSError as exc:
                raise CaptureError(f'capture read failed: {exc}') from exc
            if data:
                yield (time.time(), data, len(data))

    def close(self) -> None:
        try:
            self._sock.ioctl(SIO_RCVALL, 0)
        except OSError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass

class ScapySource(PacketSource):

    def __init__(self, interface: Optional[str]=None, snaplen: int=65535, promiscuous: bool=True):
        try:
            from scapy.sendrecv import AsyncSniffer
        except ImportError as exc:
            raise CaptureError('scapy is not installed - run: pip install scapy') from exc
        import queue
        self._queue: 'queue.Queue[Frame]' = queue.Queue(maxsize=20000)
        self._queue_module = queue

        def handler(pkt) -> None:
            try:
                raw = bytes(pkt)
                ts = float(getattr(pkt, 'time', time.time()))
                self._queue.put_nowait((ts, raw[:snaplen], len(raw)))
            except Exception:
                pass
        self._sniffer = AsyncSniffer(iface=interface, prn=handler, store=False, promisc=promiscuous)
        self._sniffer.start()
        self.name = f"scapy:{interface or 'default'}"
        self.linktype = LINKTYPE_ETHERNET

    def frames(self) -> Iterator[Frame]:
        while True:
            try:
                yield self._queue.get(timeout=0.5)
            except self._queue_module.Empty:
                yield None
                continue

    def close(self) -> None:
        try:
            self._sniffer.stop()
        except Exception:
            pass

def list_interfaces() -> List[str]:
    names: List[str] = []
    try:
        names = [name for _, name in socket.if_nameindex()]
    except (AttributeError, OSError):
        pass
    if not names:
        try:
            from scapy.arch import get_if_list
            names = list(get_if_list())
        except Exception:
            pass
    if not names and platform.system() == 'Windows':
        try:
            _host, _aliases, addresses = socket.gethostbyname_ex(socket.gethostname())
            names = addresses
        except OSError:
            pass
    return names

def open_source(interface: Optional[str]=None, pcap_file: Optional[str]=None, snaplen: int=65535, backend: str='auto', promiscuous: bool=True, realtime_replay: bool=False) -> PacketSource:
    if pcap_file:
        return PcapFileSource(pcap_file, realtime=realtime_replay)
    system = platform.system()
    if backend == 'scapy':
        return ScapySource(interface, snaplen, promiscuous)
    if backend == 'raw':
        if system == 'Windows':
            return WindowsRawSource(interface, snaplen)
        return LinuxRawSource(interface, snaplen, promiscuous)
    if system == 'Linux':
        return LinuxRawSource(interface, snaplen, promiscuous)
    if system == 'Windows':
        try:
            return ScapySource(interface, snaplen, promiscuous)
        except CaptureError:
            return WindowsRawSource(interface, snaplen)
    try:
        return ScapySource(interface, snaplen, promiscuous)
    except CaptureError as exc:
        raise CaptureError(f'no usable capture backend on {system}: {exc}. Install scapy (pip install scapy) or capture to a file with tcpdump and use -r.') from exc

def privilege_hint() -> str:
    system = platform.system()
    if system == 'Windows':
        return 'Run PowerShell as Administrator.'
    if os.geteuid() != 0 if hasattr(os, 'geteuid') else False:
        return f'Try: sudo {sys.executable} -m netscope ...'
    return ''
