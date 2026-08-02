from __future__ import annotations
import os
import struct
import sys
import tempfile
import time
import unittest
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from netscope.decoder import decode
from netscope.detect import Detector, DetectorConfig
from netscope.filters import FilterError, compile_filter
from netscope.pcap import LINKTYPE_ETHERNET, PcapReader, PcapWriter
from netscope.stats import Statistics
from netscope.utils import base_domain, shannon_entropy
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'tools'))
from make_sample_pcap import CLIENT, RESOLVER, SERVER, dns_query, dns_response, frame, icmp, ipv4, tcp, udp, CLIENT_MAC, ROUTER_MAC
NOW = 1700000000.0

def eth_frame(ip_packet: bytes) -> bytes:
    return frame(CLIENT_MAC, ROUTER_MAC, ip_packet)

class TestParsers(unittest.TestCase):

    def test_tcp_with_options(self):
        options = struct.pack('!BBH', 2, 4, 1460) + bytes([1, 1]) + struct.pack('!BBB', 3, 3, 7) + bytes(3)
        self.assertEqual(len(options), 12)
        header = struct.pack('!HHIIBBHHH', 1234, 80, 99, 0, 8 << 4, 2, 64240, 0, 0) + options
        packet = decode(eth_frame(ipv4(CLIENT, SERVER, 6, header)), NOW, LINKTYPE_ETHERNET)
        self.assertIsNotNone(packet.tcp)
        self.assertEqual(packet.tcp.sport, 1234)
        self.assertEqual(packet.tcp.dport, 80)
        self.assertEqual(packet.tcp.flag_string, 'SYN')
        self.assertTrue(packet.tcp.is_syn_only)
        self.assertIn('mss=1460', packet.tcp.options)
        self.assertIn('wscale=7', packet.tcp.options)

    def test_tcp_flag_names_and_scan_signature(self):
        xmas = decode(eth_frame(ipv4(CLIENT, SERVER, 6, tcp(1, 80, 41))), NOW)
        self.assertEqual(xmas.tcp.scan_signature, 'XMAS scan')
        null = decode(eth_frame(ipv4(CLIENT, SERVER, 6, tcp(1, 80, 0))), NOW)
        self.assertEqual(null.tcp.scan_signature, 'NULL scan')
        normal = decode(eth_frame(ipv4(CLIENT, SERVER, 6, tcp(1, 80, 24))), NOW)
        self.assertIsNone(normal.tcp.scan_signature)
        self.assertEqual(sorted(normal.tcp.flag_names), ['ACK', 'PSH'])

    def test_udp(self):
        packet = decode(eth_frame(ipv4(CLIENT, SERVER, 17, udp(5000, 6000, b'payload'))), NOW)
        self.assertIsNotNone(packet.udp)
        self.assertEqual(packet.udp.sport, 5000)
        self.assertEqual(packet.udp.dport, 6000)
        self.assertEqual(packet.payload, b'payload')

    def test_icmp_echo(self):
        packet = decode(eth_frame(ipv4(CLIENT, SERVER, 1, icmp(8, 0, 4660, 7, b'ping-data'))), NOW)
        self.assertIsNotNone(packet.icmp)
        self.assertEqual(packet.icmp.type_name, 'echo-request')
        self.assertEqual(packet.icmp.ident, 4660)
        self.assertEqual(packet.icmp.seq, 7)
        self.assertEqual(packet.payload, b'ping-data')

    def test_ip_fields(self):
        packet = decode(eth_frame(ipv4(CLIENT, SERVER, 6, tcp(1, 2, 2), ttl=53)), NOW)
        self.assertEqual(packet.ip.src, CLIENT)
        self.assertEqual(packet.ip.dst, SERVER)
        self.assertEqual(packet.ip.ttl, 53)
        self.assertEqual(packet.ip.proto_name, 'TCP')

    def test_dns_query_and_response(self):
        query = decode(eth_frame(ipv4(CLIENT, RESOLVER, 17, udp(5353, 53, dns_query(1, 'www.example.com')))), NOW)
        self.assertIsNotNone(query.dns)
        self.assertFalse(query.dns.is_response)
        self.assertEqual(query.dns.questions[0].name, 'www.example.com')
        self.assertEqual(query.dns.questions[0].type_name, 'A')
        reply = decode(eth_frame(ipv4(RESOLVER, CLIENT, 17, udp(53, 5353, dns_response(1, 'www.example.com', '1.2.3.4')))), NOW)
        self.assertTrue(reply.dns.is_response)
        self.assertEqual(reply.dns.answers[0].name, 'www.example.com')
        self.assertEqual(reply.dns.answers[0].data, '1.2.3.4')

    def test_http_request_and_response(self):
        request = b'POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Length: 9\r\n\r\nuser=bob\n'
        packet = decode(eth_frame(ipv4(CLIENT, SERVER, 6, tcp(4000, 80, 24, request))), NOW)
        self.assertIsNotNone(packet.http)
        self.assertEqual(packet.http.method, 'POST')
        self.assertEqual(packet.http.path, '/login')
        self.assertEqual(packet.http.host, 'example.com')
        self.assertEqual(packet.protocol, 'HTTP')
        response = b'HTTP/1.1 404 Not Found\r\nServer: nginx\r\n\r\n'
        packet = decode(eth_frame(ipv4(SERVER, CLIENT, 6, tcp(80, 4000, 24, response))), NOW)
        self.assertEqual(packet.http.kind, 'response')
        self.assertEqual(packet.http.status, 404)

    def test_truncated_frame_does_not_raise(self):
        packet = decode(b'short', NOW)
        self.assertTrue(packet.errors)
        self.assertEqual(packet.protocol, 'UNKNOWN')

class TestFilters(unittest.TestCase):

    def setUp(self):
        self.http = decode(eth_frame(ipv4(CLIENT, SERVER, 6, tcp(44000, 80, 24, b'GET / HTTP/1.1\r\nHost: x\r\n\r\n'))), NOW)
        self.dns = decode(eth_frame(ipv4(CLIENT, RESOLVER, 17, udp(5353, 53, dns_query(2, 'a.example.com')))), NOW)
        self.ping = decode(eth_frame(ipv4(CLIENT, SERVER, 1, icmp(8, 0, 1, 1, b'x' * 40))), NOW)

    def check(self, expression, expected):
        predicate = compile_filter(expression)
        self.assertEqual([predicate(self.http), predicate(self.dns), predicate(self.ping)], expected, f'filter: {expression}')

    def test_protocol_keywords(self):
        self.check('tcp', [True, False, False])
        self.check('udp', [False, True, False])
        self.check('icmp', [False, False, True])
        self.check('dns', [False, True, False])
        self.check('http', [True, False, False])

    def test_boolean_logic(self):
        self.check('tcp or icmp', [True, False, True])
        self.check('not tcp', [False, True, True])
        self.check('udp and port 53', [False, True, False])
        self.check('(tcp or udp) and not http', [False, True, False])

    def test_implicit_and(self):
        self.check('tcp port 80', [True, False, False])

    def test_hosts_ports_nets(self):
        self.check(f'host {SERVER}', [True, False, True])
        self.check(f'dst host {RESOLVER}', [False, True, False])
        self.check('net 192.168.1.0/24', [True, True, True])
        self.check('dport 80', [True, False, False])
        self.check('portrange 50-100', [True, True, False])

    def test_flags_length_payload(self):
        self.check('tcp-flag psh', [True, False, False])
        self.check('len > 1000', [False, False, False])
        self.check('payload example.com', [False, False, False])
        self.check('payload "GET"', [True, False, False])

    def test_empty_filter_matches_all(self):
        self.check(None, [True, True, True])

    def test_bad_filter_raises(self):
        with self.assertRaises(FilterError):
            compile_filter('tcp and')
        with self.assertRaises(FilterError):
            compile_filter('bogus-keyword')
        with self.assertRaises(FilterError):
            compile_filter('(tcp')

class TestPcapRoundTrip(unittest.TestCase):

    def test_write_then_read(self):
        payloads = [eth_frame(ipv4(CLIENT, SERVER, 6, tcp(i, 80, 2))) for i in range(1, 6)]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'out.pcap')
            with PcapWriter(path, linktype=LINKTYPE_ETHERNET) as writer:
                for index, data in enumerate(payloads):
                    writer.write(NOW + index * 0.25, data)
                self.assertEqual(writer.count, 5)
            with PcapReader(path) as reader:
                self.assertEqual(reader.linktype, LINKTYPE_ETHERNET)
                records = list(reader)
        self.assertEqual(len(records), 5)
        self.assertEqual([data for _, data, _ in records], payloads)
        self.assertAlmostEqual(records[1][0], NOW + 0.25, places=5)

    def test_rejects_non_pcap(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'bad.bin')
            with open(path, 'wb') as handle:
                handle.write(b'not a pcap file at all, really')
            with self.assertRaises(ValueError):
                PcapReader(path)

class TestStatistics(unittest.TestCase):

    def test_counters(self):
        stats = Statistics()
        for index in range(4):
            stats.add(decode(eth_frame(ipv4(CLIENT, SERVER, 6, tcp(1000 + index, 443, 24, b'x' * 100))), NOW + index))
        stats.add(decode(eth_frame(ipv4(CLIENT, RESOLVER, 17, udp(5353, 53, dns_query(1, 'example.com')))), NOW + 5))
        stats.skip()
        self.assertEqual(stats.packets, 5)
        self.assertEqual(stats.filtered_out, 1)
        self.assertEqual(stats.protocols['TCP'], 4)
        self.assertEqual(stats.protocols['DNS'], 1)
        self.assertEqual(stats.talkers[CLIENT], stats.bytes)
        self.assertEqual(stats.dst_ports['TCP/443'], 4)
        self.assertGreater(stats.average_packet_size, 0)

class TestDetection(unittest.TestCase):

    def rules_fired(self, packets):
        detector = Detector(DetectorConfig(cooldown=0.0))
        fired = set()
        for packet in packets:
            for alert in detector.feed(packet):
                fired.add(alert.rule)
        return fired

    def test_port_scan(self):
        packets = [decode(eth_frame(ipv4('192.168.1.66', '192.168.1.10', 6, tcp(40000 + i, 1000 + i, 2))), NOW + i * 0.01) for i in range(25)]
        self.assertIn('port-scan', self.rules_fired(packets))

    def test_port_scan_below_threshold_is_quiet(self):
        packets = [decode(eth_frame(ipv4('192.168.1.66', '192.168.1.10', 6, tcp(40000 + i, 1000 + i, 2))), NOW + i * 0.01) for i in range(5)]
        self.assertNotIn('port-scan', self.rules_fired(packets))

    def test_stealth_scan(self):
        packets = [decode(eth_frame(ipv4(CLIENT, SERVER, 6, tcp(1, 80, 41))), NOW)]
        self.assertIn('stealth-scan', self.rules_fired(packets))

    def test_syn_flood(self):
        packets = [decode(eth_frame(ipv4(f'10.0.0.{i % 200 + 1}', '192.168.1.10', 6, tcp(30000 + i, 80, 2))), NOW + i * 0.001) for i in range(130)]
        self.assertIn('syn-flood', self.rules_fired(packets))

    def test_ping_sweep(self):
        packets = [decode(eth_frame(ipv4('192.168.1.66', f'192.168.1.{host}', 1, icmp(8, 0, 1, host, b'sweep'))), NOW + host * 0.01) for host in range(1, 25)]
        self.assertIn('ping-sweep', self.rules_fired(packets))

    def test_icmp_tunnel(self):
        payload = bytes(((i * 37 + 11) % 251 for i in range(600)))
        packets = [decode(eth_frame(ipv4(CLIENT, '203.0.113.77', 1, icmp(8, 0, 1, 1, payload))), NOW)]
        self.assertIn('icmp-tunnel', self.rules_fired(packets))

    def test_normal_ping_is_not_a_tunnel(self):
        packets = [decode(eth_frame(ipv4(CLIENT, SERVER, 1, icmp(8, 0, 1, 1, bytes(range(32, 88))))), NOW)]
        self.assertNotIn('icmp-tunnel', self.rules_fired(packets))

    def test_dns_tunnel_high_entropy_label(self):
        label = 'k7x2q9zv4m1p8w3ejr6ty5unbh0acdfgislo2q7x9k4mzv1p8w3e'
        query = dns_query(1, f'{label}.tunnel.example.com', qtype=16)
        packets = [decode(eth_frame(ipv4(CLIENT, RESOLVER, 17, udp(5000, 53, query))), NOW)]
        fired = self.rules_fired(packets)
        self.assertIn('dns-tunnel', fired)
        self.assertIn('dns-rare-qtype', fired)

    def test_dns_tunnel_many_subdomains(self):
        packets = []
        for i in range(35):
            query = dns_query(i, f'chunk{i:04d}.tunnel.example.com')
            packets.append(decode(eth_frame(ipv4(CLIENT, RESOLVER, 17, udp(5000 + i, 53, query))), NOW + i * 0.1))
        self.assertIn('dns-tunnel-volume', self.rules_fired(packets))

    def test_normal_dns_is_quiet(self):
        packets = [decode(eth_frame(ipv4(CLIENT, RESOLVER, 17, udp(5000, 53, dns_query(1, name)))), NOW) for name in ('www.google.com', 'api.github.com', 'cdn.example.org')]
        self.assertEqual(self.rules_fired(packets), set())

    def test_http_basic_auth_credentials(self):
        request = b'GET /admin HTTP/1.1\r\nHost: intranet\r\nAuthorization: Basic YWRtaW46aHVudGVyMg==\r\n\r\n'
        packets = [decode(eth_frame(ipv4(CLIENT, '192.168.1.10', 6, tcp(4000, 80, 24, request))), NOW)]
        self.assertIn('cleartext-credentials', self.rules_fired(packets))

    def test_http_password_field(self):
        body = b'user=alice&password=SuperSecret1'
        request = b'POST /login HTTP/1.1\r\nHost: intranet\r\nContent-Length: 32\r\n\r\n' + body
        packets = [decode(eth_frame(ipv4(CLIENT, '192.168.1.10', 6, tcp(4001, 80, 24, request))), NOW)]
        self.assertIn('cleartext-credentials', self.rules_fired(packets))

    def test_ftp_credentials(self):
        packets = [decode(eth_frame(ipv4(CLIENT, '192.168.1.10', 6, tcp(4002, 21, 24, b'PASS letmein\r\n'))), NOW)]
        self.assertIn('cleartext-credentials', self.rules_fired(packets))

    def test_suspicious_port(self):
        packets = [decode(eth_frame(ipv4(CLIENT, '203.0.113.77', 6, tcp(45000, 4444, 2))), NOW)]
        self.assertIn('suspicious-port', self.rules_fired(packets))

    def test_data_egress(self):
        packets = [decode(eth_frame(ipv4(CLIENT, '203.0.113.77', 6, tcp(46000, 443, 24, bytes(1400)))), NOW + i * 0.01) for i in range(4000)]
        self.assertIn('data-egress', self.rules_fired(packets))

    def test_cooldown_suppresses_duplicates(self):
        detector = Detector(DetectorConfig(cooldown=60.0))
        total = 0
        for i in range(3):
            packet = decode(eth_frame(ipv4(CLIENT, '203.0.113.77', 6, tcp(45000, 4444, 2))), NOW + i)
            total += len(detector.feed(packet))
        self.assertEqual(total, 1)

class TestUtils(unittest.TestCase):

    def test_entropy(self):
        self.assertEqual(shannon_entropy(b''), 0.0)
        self.assertEqual(shannon_entropy(b'aaaaaaaa'), 0.0)
        self.assertGreater(shannon_entropy(bytes(range(256))), 7.9)

    def test_base_domain(self):
        self.assertEqual(base_domain('a.b.example.com'), 'example.com')
        self.assertEqual(base_domain('example.com'), 'example.com')
        self.assertEqual(base_domain('localhost'), 'localhost')
if __name__ == '__main__':
    unittest.main(verbosity=2)
