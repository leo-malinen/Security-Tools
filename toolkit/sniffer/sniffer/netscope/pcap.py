from __future__ import annotations
import struct
from typing import BinaryIO, Iterator, Optional, Tuple
MAGIC_USEC = 2712847316
MAGIC_NSEC = 2712812621
PCAPNG_MAGIC = bytes.fromhex('0a0d0d0a')
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_NULL = 0

class PcapWriter:

    def __init__(self, path: str, linktype: int=LINKTYPE_ETHERNET, snaplen: int=65535):
        self.path = path
        self.linktype = linktype
        self.snaplen = snaplen
        self.count = 0
        self._fh: BinaryIO = open(path, 'wb')
        self._fh.write(struct.pack('<IHHiIII', MAGIC_USEC, 2, 4, 0, 0, snaplen, linktype))
        self._fh.flush()

    def write(self, ts: float, data: bytes, wire_length: Optional[int]=None) -> None:
        if self._fh.closed:
            raise ValueError('writer is closed')
        captured = data[:self.snaplen]
        sec = int(ts)
        usec = int(round((ts - sec) * 1000000))
        if usec >= 1000000:
            sec += 1
            usec -= 1000000
        self._fh.write(struct.pack('<IIII', sec, usec, len(captured), wire_length or len(data)))
        self._fh.write(captured)
        self._fh.flush()
        self.count += 1

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.close()

    def __enter__(self) -> 'PcapWriter':
        return self

    def __exit__(self, *exc) -> None:
        self.close()

class PcapReader:

    def __init__(self, path: str):
        self.path = path
        self._fh: BinaryIO = open(path, 'rb')
        header = self._fh.read(24)
        if len(header) < 24:
            raise ValueError(f'{path}: too short to be a pcap file')
        magic = struct.unpack('<I', header[:4])[0]
        if magic in (MAGIC_USEC, MAGIC_NSEC):
            self.endian = '<'
        else:
            magic = struct.unpack('>I', header[:4])[0]
            if magic not in (MAGIC_USEC, MAGIC_NSEC):
                if header[:4] == PCAPNG_MAGIC:
                    raise ValueError(f'{path}: this is a pcapng file; convert it first (editcap -F pcap in.pcapng out.pcap)')
                raise ValueError(f'{path}: not a pcap file (bad magic)')
            self.endian = '>'
        self.nanosecond = magic == MAGIC_NSEC
        fields = struct.unpack(self.endian + 'HHiIII', header[4:])
        self.version = (fields[0], fields[1])
        self.snaplen = fields[4]
        self.linktype = fields[5]

    def __iter__(self) -> Iterator[Tuple[float, bytes, int]]:
        divisor = 1000000000.0 if self.nanosecond else 1000000.0
        while True:
            rec = self._fh.read(16)
            if len(rec) < 16:
                return
            sec, frac, caplen, wirelen = struct.unpack(self.endian + 'IIII', rec)
            data = self._fh.read(caplen)
            if len(data) < caplen:
                return
            yield (sec + frac / divisor, data, wirelen)

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.close()

    def __enter__(self) -> 'PcapReader':
        return self

    def __exit__(self, *exc) -> None:
        self.close()
