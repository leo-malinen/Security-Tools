from __future__ import annotations
import argparse
import json
import os
import platform
import signal
import sys
import time
from typing import List, Optional
from .capture import CaptureError, list_interfaces, open_source, privilege_hint
from .decoder import decode
from .detect import SUSPICIOUS_PORTS, Alert, Detector, DetectorConfig
from .filters import FilterError, compile_filter
from .models import Packet
from .pcap import PcapWriter
from .stats import CLEAR_SCREEN, Statistics, render_dashboard, supports_ansi, text_summary
from .utils import hexdump
SEVERITY_LEVELS = ('info', 'low', 'medium', 'high')

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='netscope', description='Packet sniffer with TCP/UDP/ICMP/DNS/HTTP decoding, filtering, live statistics, pcap export and suspicious-traffic detection.', formatter_class=argparse.RawDescriptionHelpFormatter, epilog="examples:\n  sudo python3 -m netscope -i eth0\n  sudo python3 -m netscope -i eth0 -f 'tcp and port 80' --lines\n  sudo python3 -m netscope -i eth0 -w capture.pcap -c 5000\n  python3 -m netscope -r capture.pcap --lines --alerts-only\n  python3 -m netscope -r capture.pcap --json-alerts alerts.json\n")
    source = parser.add_argument_group('capture source')
    source.add_argument('-i', '--interface', help='interface to capture on (eth0, wlan0, ...)')
    source.add_argument('-r', '--read', metavar='FILE', help='read packets from a pcap file instead')
    source.add_argument('--backend', choices=('auto', 'raw', 'scapy'), default='auto', help='capture backend: raw sockets, scapy/libpcap, or auto-detect (default)')
    source.add_argument('--snaplen', type=int, default=65535, help='bytes to capture per packet')
    source.add_argument('--no-promiscuous', action='store_true', help='do not put the interface in promiscuous mode')
    source.add_argument('--realtime-replay', action='store_true', help='when reading a file, sleep between packets to mimic original timing')
    source.add_argument('-L', '--list-interfaces', action='store_true', help='list interfaces and exit')
    output = parser.add_argument_group('output')
    output.add_argument('-w', '--write', metavar='FILE', help='write captured packets to a pcap file')
    output.add_argument('--lines', action='store_true', help='print one line per packet instead of the live dashboard')
    output.add_argument('-x', '--hexdump', action='store_true', help='hex dump each payload (implies --lines)')
    output.add_argument('--alerts-only', action='store_true', help='only print detection alerts')
    output.add_argument('-q', '--quiet', action='store_true', help='suppress per-packet output entirely')
    output.add_argument('--interval', type=float, default=1.0, help='dashboard refresh interval in seconds (default 1.0)')
    output.add_argument('--json-alerts', metavar='FILE', help='write alerts as JSON on exit')
    output.add_argument('--no-summary', action='store_true', help='skip the end-of-capture summary')
    control = parser.add_argument_group('filtering and limits')
    control.add_argument('-f', '--filter', metavar='EXPR', help='filter expression, e.g. "tcp and port 443" or "dns or icmp"')
    control.add_argument('-c', '--count', type=int, help='stop after this many matching packets')
    control.add_argument('-t', '--duration', type=float, help='stop after this many seconds')
    detection = parser.add_argument_group('detection')
    detection.add_argument('--no-detect', action='store_true', help='disable suspicious-traffic detection')
    detection.add_argument('--min-severity', choices=SEVERITY_LEVELS, default='low', help='lowest severity to report (default low)')
    detection.add_argument('--port-scan-ports', type=int, default=20, help='distinct ports that trigger a port-scan alert')
    detection.add_argument('--port-scan-window', type=float, default=10.0, help='port-scan window in seconds')
    detection.add_argument('--syn-flood-count', type=int, default=120, help='SYNs per window that trigger a flood alert')
    detection.add_argument('--dns-tunnel-subdomains', type=int, default=30, help='unique subdomains that trigger a DNS tunnel alert')
    detection.add_argument('--exfil-mb', type=float, default=5.0, help='MB to one external host that triggers a data-egress alert')
    detection.add_argument('--cooldown', type=float, default=30.0, help='seconds before the same alert repeats')
    detection.add_argument('--show-rules', action='store_true', help='describe the detection rules and exit')
    return parser

def describe_rules() -> str:
    lines = ['detection rules', '===============', 'port-scan             one source hitting many ports on one host (SYN only)', 'host-sweep            one source sending SYNs to many distinct hosts', 'ping-sweep            one source sending ICMP echo requests to many hosts', 'stealth-scan          abnormal TCP flag combinations: NULL, FIN, XMAS, SYN+FIN', 'syn-flood             high volume of half-open connections to one service', 'dns-tunnel            long, high-entropy DNS labels (encoded data in queries)', 'dns-tunnel-volume     many unique subdomains of one parent domain', 'dns-rare-qtype        TXT / NULL / ANY queries, uncommon from normal clients', 'icmp-tunnel           oversized, high-entropy ICMP echo payloads', 'cleartext-credentials HTTP Basic auth, password form fields, FTP/telnet USER+PASS', 'suspicious-port       traffic on known backdoor / C2 / remote-shell ports', 'data-egress           large volume from a private host to a single public host', '', 'watched ports', '-------------']
    for port in sorted(SUSPICIOUS_PORTS):
        lines.append(f'  {port:<6} {SUSPICIOUS_PORTS[port]}')
    lines += ['', 'These are heuristics tuned for small networks. On busy links, raise the', 'thresholds (--port-scan-ports, --syn-flood-count, ...) to cut false positives.']
    return '\n'.join(lines)

def format_packet_line(packet: Packet, index: int) -> str:
    stamp = time.strftime('%H:%M:%S', time.localtime(packet.ts))
    millis = int(packet.ts % 1 * 1000)
    return f'{index:>6} {stamp}.{millis:03d} {packet.summary()}'

def format_alert_line(alert: Alert) -> str:
    stamp = time.strftime('%H:%M:%S', time.localtime(alert.ts))
    return f'  !! [{alert.severity.upper():<6}] {stamp} {alert.rule}: {alert.message}'

def main(argv: Optional[List[str]]=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.show_rules:
        print(describe_rules())
        return 0
    if args.list_interfaces:
        names = list_interfaces()
        if not names:
            print('no interfaces found (try installing scapy, or run with more privileges)')
            return 1
        print('available interfaces:')
        for name in names:
            print(f'  {name}')
        return 0
    if not args.interface and (not args.read):
        parser.error('specify a capture interface with -i, or a pcap file with -r')
    try:
        packet_filter = compile_filter(args.filter)
    except FilterError as exc:
        print(f'bad filter: {exc}', file=sys.stderr)
        return 2
    config = DetectorConfig(port_scan_ports=args.port_scan_ports, port_scan_window=args.port_scan_window, syn_flood_count=args.syn_flood_count, dns_tunnel_subdomains=args.dns_tunnel_subdomains, exfil_bytes=int(args.exfil_mb * 1024 * 1024), cooldown=args.cooldown)
    detector = None if args.no_detect else Detector(config)
    min_severity_rank = SEVERITY_LEVELS.index(args.min_severity)
    try:
        source = open_source(interface=args.interface, pcap_file=args.read, snaplen=args.snaplen, backend=args.backend, promiscuous=not args.no_promiscuous, realtime_replay=args.realtime_replay)
    except CaptureError as exc:
        print(f'capture error: {exc}', file=sys.stderr)
        hint = privilege_hint()
        if hint:
            print(hint, file=sys.stderr)
        return 3
    except (OSError, ValueError) as exc:
        print(f'could not open source: {exc}', file=sys.stderr)
        return 3
    writer: Optional[PcapWriter] = None
    if args.write:
        try:
            writer = PcapWriter(args.write, linktype=source.linktype, snaplen=args.snaplen)
        except OSError as exc:
            print(f'could not open {args.write} for writing: {exc}', file=sys.stderr)
            source.close()
            return 3
    stop = {'flag': False}

    def handle_signal(_signum, _frame) -> None:
        stop['flag'] = True
    signal.signal(signal.SIGINT, handle_signal)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, handle_signal)
    stats = Statistics()
    alerts: List[Alert] = []
    line_mode = args.lines or args.hexdump or args.alerts_only or (not source.live)
    dashboard = not line_mode and (not args.quiet) and supports_ansi()
    last_render = 0.0
    matched = 0
    started = time.time()
    if line_mode and (not args.quiet):
        print(f'capturing on {source.name} (linktype {source.linktype})', file=sys.stderr)
        if args.filter:
            print(f'filter: {args.filter}', file=sys.stderr)
    try:
        for frame in source.frames():
            if stop['flag']:
                break
            if args.duration and time.time() - started >= args.duration:
                break
            if frame is None:
                if dashboard and time.time() - last_render >= args.interval:
                    sys.stdout.write(CLEAR_SCREEN + render_dashboard(stats, alerts, source.name, args.filter, args.write, writer.count if writer else 0) + '\n')
                    sys.stdout.flush()
                    last_render = time.time()
                continue
            ts, data, wirelen = frame
            packet = decode(data, ts, source.linktype, wirelen)
            if not packet_filter(packet):
                stats.skip()
                continue
            matched += 1
            stats.add(packet)
            if writer is not None:
                writer.write(packet.ts, data, wirelen)
            new_alerts: List[Alert] = []
            if detector is not None:
                new_alerts = [alert for alert in detector.feed(packet) if SEVERITY_LEVELS.index(alert.severity) >= min_severity_rank]
                alerts.extend(new_alerts)
            if not args.quiet:
                if line_mode:
                    if not args.alerts_only:
                        print(format_packet_line(packet, matched))
                        if args.hexdump and packet.payload:
                            print(hexdump(packet.payload))
                    for alert in new_alerts:
                        print(format_alert_line(alert))
                elif dashboard and time.time() - last_render >= args.interval:
                    sys.stdout.write(CLEAR_SCREEN + render_dashboard(stats, alerts, source.name, args.filter, args.write, writer.count if writer else 0) + '\n')
                    sys.stdout.flush()
                    last_render = time.time()
            if args.count and matched >= args.count:
                break
    except CaptureError as exc:
        print(f'capture stopped: {exc}', file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        pass
    finally:
        source.close()
        if writer is not None:
            writer.close()
    if dashboard:
        sys.stdout.write(CLEAR_SCREEN)
        sys.stdout.flush()
    if not args.no_summary:
        print(text_summary(stats, alerts))
        if writer is not None:
            print(f'\nwrote {writer.count} packets to {args.write}')
    if args.json_alerts:
        payload = {'source': source.name, 'filter': args.filter, 'generated_at': time.time(), 'packets': stats.packets, 'bytes': stats.bytes, 'alerts': [alert.to_dict() for alert in alerts]}
        try:
            with open(args.json_alerts, 'w', encoding='utf-8') as handle:
                json.dump(payload, handle, indent=2)
            print(f'wrote {len(alerts)} alerts to {args.json_alerts}')
        except OSError as exc:
            print(f'could not write {args.json_alerts}: {exc}', file=sys.stderr)
            return 4
    return 0
if __name__ == '__main__':
    sys.exit(main())
