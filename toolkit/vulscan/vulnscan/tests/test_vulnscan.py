from __future__ import annotations

import os
import socket
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vulnscan.banners import grab_banner
from vulnscan.cve import CVEDatabase
from vulnscan.discovery import expand_targets, host_is_up, parse_ports
from vulnscan.engine import VulnScanner
from vulnscan.models import ScanReport, severity_from_cvss
from vulnscan.report import build_pdf, render_html, render_json, render_text, write_html, write_pdf
from vulnscan.scanner import scan_ports
from vulnscan.services import classify, service_for_port
from vulnscan.versions import compare_versions, cpe_for, identify_product, is_outdated, satisfies

CRLF = chr(13) + chr(10)

FTP_BANNER = "220 (vsFTPd 2.3.4)" + CRLF
SSH_BANNER = "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8" + CRLF
HTTP_BANNER = "HTTP/1.1 200 OK" + CRLF + "Server: Apache/2.4.49 (Unix)" + CRLF + CRLF


class FakeService:
    def __init__(self, banner: str, wait_for_request: bool = False):
        self.banner = banner.encode()
        self.wait_for_request = wait_for_request
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(8)
        self.port = self.server.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn.settimeout(2.0)
            if self.wait_for_request:
                try:
                    conn.recv(2048)
                except socket.timeout:
                    pass
            conn.sendall(self.banner)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        try:
            self.server.close()
        except OSError:
            pass


def free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class TestTargetAndPortParsing(unittest.TestCase):
    def test_single_host(self):
        self.assertEqual(expand_targets("127.0.0.1"), ["127.0.0.1"])

    def test_hostname_preserved(self):
        self.assertEqual(expand_targets("example.com"), ["example.com"])

    def test_cidr(self):
        hosts = expand_targets("192.168.1.0/30")
        self.assertEqual(hosts, ["192.168.1.1", "192.168.1.2"])

    def test_last_octet_range(self):
        hosts = expand_targets("10.0.0.5-8")
        self.assertEqual(hosts, ["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"])

    def test_full_range_and_dedupe(self):
        hosts = expand_targets("10.0.0.1-10.0.0.3, 10.0.0.1")
        self.assertEqual(hosts, ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_multiple_tokens(self):
        hosts = expand_targets(["127.0.0.1", "10.0.0.1 10.0.0.2"])
        self.assertEqual(hosts, ["127.0.0.1", "10.0.0.1", "10.0.0.2"])

    def test_parse_ports_list_and_range(self):
        self.assertEqual(parse_ports("22,80,100-103"), [22, 80, 100, 101, 102, 103])

    def test_parse_ports_default(self):
        self.assertIn(443, parse_ports(None))

    def test_parse_ports_filters_invalid(self):
        self.assertEqual(parse_ports("0 22 70000"), [22])


class TestVersionLogic(unittest.TestCase):
    def test_compare_numeric(self):
        self.assertEqual(compare_versions("2.4.51", "2.4.49"), 1)
        self.assertEqual(compare_versions("1.4.0", "1.4.0"), 0)
        self.assertEqual(compare_versions("1.2.3", "1.10.0"), -1)

    def test_compare_with_suffix(self):
        self.assertEqual(compare_versions("7.2p2", "7.2"), 1)
        self.assertEqual(compare_versions("7.2p2", "7.7"), -1)

    def test_satisfies_operators(self):
        self.assertTrue(satisfies("7.2p2", "<7.7"))
        self.assertFalse(satisfies("8.0", "<7.7"))
        self.assertTrue(satisfies("2.3.4", "==2.3.4"))
        self.assertTrue(satisfies("2.4.50", ">=2.4.49 <=2.4.50"))
        self.assertFalse(satisfies("2.4.51", ">=2.4.49 <=2.4.50"))
        self.assertTrue(satisfies("1.0.1f", ">=1.0.1 <1.0.1g"))

    def test_identify_products(self):
        self.assertEqual(identify_product(SSH_BANNER), ("ssh", "OpenSSH", "7.2p2"))
        self.assertEqual(identify_product(FTP_BANNER), ("ftp", "vsftpd", "2.3.4"))
        self.assertEqual(identify_product(HTTP_BANNER), ("http", "Apache httpd", "2.4.49"))
        self.assertEqual(identify_product("Server: nginx/1.4.0"), ("http", "nginx", "1.4.0"))

    def test_identify_unknown(self):
        self.assertEqual(identify_product("gibberish"), (None, None, None))

    def test_outdated_detection(self):
        outdated, latest = is_outdated("OpenSSH", "7.2p2")
        self.assertTrue(outdated)
        self.assertEqual(latest, "9.8p1")

    def test_not_outdated(self):
        outdated, _ = is_outdated("nginx", "99.0")
        self.assertFalse(outdated)

    def test_cpe(self):
        self.assertEqual(
            cpe_for("Apache httpd", "2.4.49"),
            "cpe:2.3:a:apache_httpd:apache_httpd:2.4.49:*:*:*:*:*:*:*",
        )


class TestServiceDetection(unittest.TestCase):
    def test_port_map(self):
        self.assertEqual(service_for_port(22), "ssh")
        self.assertEqual(service_for_port(3306), "mysql")
        self.assertIsNone(service_for_port(64999))

    def test_classify_prefers_banner(self):
        service, product, version = classify(9999, SSH_BANNER)
        self.assertEqual((service, product, version), ("ssh", "OpenSSH", "7.2p2"))

    def test_classify_falls_back_to_port(self):
        service, product, version = classify(3389, None)
        self.assertEqual(service, "rdp")
        self.assertIsNone(product)
        self.assertIsNone(version)


class TestScanning(unittest.TestCase):
    def setUp(self):
        self.service = FakeService(FTP_BANNER)
        self.addCleanup(self.service.close)

    def test_finds_open_port(self):
        closed = free_port()
        results = scan_ports("127.0.0.1", [self.service.port, closed], timeout=1.0, workers=8)
        self.assertEqual([r.port for r in results], [self.service.port])
        self.assertEqual(results[0].state, "open")

    def test_progress_callback(self):
        seen = []
        scan_ports("127.0.0.1", [self.service.port], timeout=1.0, workers=2, progress=lambda d, t: seen.append((d, t)))
        self.assertEqual(seen, [(1, 1)])

    def test_empty_port_list(self):
        self.assertEqual(scan_ports("127.0.0.1", [], timeout=0.5), [])

    def test_host_is_up(self):
        self.assertTrue(host_is_up("127.0.0.1", ports=[self.service.port], timeout=1.0))
        self.assertFalse(host_is_up("127.0.0.1", ports=[free_port()], timeout=0.5))


class TestBanners(unittest.TestCase):
    def test_grab_speak_first_banner(self):
        service = FakeService(SSH_BANNER)
        self.addCleanup(service.close)
        banner = grab_banner("127.0.0.1", service.port, timeout=2.0)
        self.assertIsNotNone(banner)
        self.assertIn("OpenSSH_7.2p2", banner)

    def test_grab_http_banner(self):
        service = FakeService(HTTP_BANNER)
        self.addCleanup(service.close)
        banner = grab_banner("127.0.0.1", service.port, timeout=2.0)
        self.assertIn("Apache/2.4.49", banner)

    def test_closed_port_returns_none(self):
        self.assertIsNone(grab_banner("127.0.0.1", free_port(), timeout=0.5))


class TestCVELookup(unittest.TestCase):
    def setUp(self):
        self.db = CVEDatabase.load()

    def test_vsftpd_backdoor(self):
        vulns = self.db.lookup("vsftpd", "2.3.4")
        self.assertEqual([v.cve_id for v in vulns], ["CVE-2011-2523"])
        self.assertEqual(vulns[0].severity, "critical")

    def test_vsftpd_patched(self):
        self.assertEqual(self.db.lookup("vsftpd", "3.0.5"), [])

    def test_apache_sorted_by_score(self):
        vulns = self.db.lookup("Apache httpd", "2.4.49")
        ids = [v.cve_id for v in vulns]
        self.assertIn("CVE-2021-42013", ids)
        self.assertIn("CVE-2021-41773", ids)
        self.assertEqual(ids[0], "CVE-2021-42013")
        self.assertGreaterEqual(vulns[0].cvss, vulns[-1].cvss)

    def test_openssh_range(self):
        ids = [v.cve_id for v in self.db.lookup("OpenSSH", "7.2p2")]
        self.assertIn("CVE-2018-15473", ids)

    def test_unknown_product(self):
        self.assertEqual(self.db.lookup("NotARealDaemon", "1.0"), [])

    def test_severity_mapping(self):
        self.assertEqual(severity_from_cvss(9.8), "critical")
        self.assertEqual(severity_from_cvss(7.5), "high")
        self.assertEqual(severity_from_cvss(5.0), "medium")
        self.assertEqual(severity_from_cvss(1.0), "low")
        self.assertEqual(severity_from_cvss(0.0), "none")


class TestEndToEnd(unittest.TestCase):
    def setUp(self):
        self.ftp = FakeService(FTP_BANNER)
        self.ssh = FakeService(SSH_BANNER)
        self.addCleanup(self.ftp.close)
        self.addCleanup(self.ssh.close)
        scanner = VulnScanner(
            ports=[self.ftp.port, self.ssh.port, free_port()],
            timeout=1.5,
            workers=8,
            grab_banners=True,
            cve_db=CVEDatabase.load(),
            skip_discovery=True,
        )
        self.report = scanner.run("127.0.0.1")

    def test_report_shape(self):
        self.assertEqual(len(self.report.hosts), 1)
        host = self.report.hosts[0]
        self.assertTrue(host.alive)
        self.assertEqual(len(host.open_ports), 2)

    def test_products_detected(self):
        products = {p.product for p in self.report.hosts[0].open_ports}
        self.assertEqual(products, {"vsftpd", "OpenSSH"})

    def test_outdated_flagged(self):
        self.assertTrue(all(p.outdated for p in self.report.hosts[0].open_ports))

    def test_cves_attached(self):
        ids = {v.cve_id for v in self.report.hosts[0].vulnerabilities}
        self.assertIn("CVE-2011-2523", ids)
        self.assertIn("CVE-2018-15473", ids)

    def test_risk_is_critical(self):
        self.assertEqual(self.report.hosts[0].risk, "critical")

    def test_severity_counts(self):
        counts = self.report.severity_counts()
        self.assertGreaterEqual(counts["critical"], 1)

    def test_text_report(self):
        text = "\n".join(render_text(self.report))
        self.assertIn("vulnscan report", text)
        self.assertIn("CVE-2011-2523", text)
        self.assertIn("outdated", text)

    def test_html_report(self):
        markup = render_html(self.report)
        self.assertIn("<!doctype html>", markup)
        self.assertIn("CVE-2011-2523", markup)
        self.assertIn("127.0.0.1", markup)
        self.assertIn("critical", markup)

    def test_json_report(self):
        payload = render_json(self.report)
        self.assertIn("CVE-2011-2523", payload)
        self.assertIn("severity_counts", payload)

    def test_written_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            html_path = os.path.join(tmp, "r.html")
            pdf_path = os.path.join(tmp, "r.pdf")
            write_html(self.report, html_path)
            write_pdf(self.report, pdf_path)
            with open(html_path, encoding="utf-8") as handle:
                self.assertIn("CVE-2011-2523", handle.read())
            with open(pdf_path, "rb") as handle:
                data = handle.read()
            self.assertTrue(data.startswith(b"%PDF-1.4"))
            self.assertTrue(data.rstrip().endswith(b"%%EOF"))


class TestPdfWriter(unittest.TestCase):
    def test_structure(self):
        data = build_pdf(["hello", "world (test)"])
        self.assertTrue(data.startswith(b"%PDF-1.4"))
        self.assertIn(b"/Type /Catalog", data)
        self.assertIn(b"/BaseFont /Courier", data)
        self.assertIn(b"startxref", data)
        self.assertTrue(data.rstrip().endswith(b"%%EOF"))

    def test_escaping(self):
        data = build_pdf(["a (b) c"])
        self.assertIn(b"a " + bytes([92]) + b"(b" + bytes([92]) + b") c", data)

    def test_pagination(self):
        many = [f"line {i}" for i in range(200)]
        data = build_pdf(many)
        self.assertGreater(data.count(b"/Type /Page "), 1)

    def test_xref_offsets_are_valid(self):
        data = build_pdf(["one", "two"])
        marker = data.rindex(b"startxref")
        offset = int(data[marker + len(b"startxref"):].split()[0])
        self.assertEqual(data[offset:offset + 4], b"xref")


class TestEmptyReport(unittest.TestCase):
    def test_renders_without_hosts(self):
        report = ScanReport(targets=["10.0.0.1"], started=1.0, finished=2.0)
        self.assertIn("vulnscan report", "\n".join(render_text(report)))
        self.assertIn("open ports", render_html(report))
        self.assertTrue(build_pdf(render_text(report)).startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
