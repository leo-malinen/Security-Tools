from __future__ import annotations

import argparse
import sys
import time
from typing import List, Optional

from .cve import CVEDatabase
from .discovery import parse_ports
from .engine import VulnScanner
from .models import SEVERITY_ORDER
from .report import render_text, write_html, write_json, write_pdf
from .services import TOP_PORTS

BANNER = (
    "vulnscan - authorized testing only. Scan hosts and networks you own or "
    "have explicit written permission to assess."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description="Port discovery, service and version detection, banner grabbing, "
        "outdated-software checks, offline/online CVE lookups and HTML/PDF reporting.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python3 -m vulnscan 192.168.1.10\n"
            "  python3 -m vulnscan 10.0.0.0/24 --top 20 --html report.html\n"
            "  python3 -m vulnscan scanme.example.com -p 1-1024 -o report\n"
            "  python3 -m vulnscan 192.168.1.5 --online --pdf report.pdf\n"
        ),
    )
    parser.add_argument("targets", nargs="*", help="hosts, hostnames, CIDR ranges, or a.b.c.d-e ranges")

    scan = parser.add_argument_group("scan")
    scan.add_argument("-p", "--ports", help="ports to scan, e.g. 22,80,443 or 1-1024")
    scan.add_argument("--top", type=int, metavar="N", help="scan the top N common ports")
    scan.add_argument("--timeout", type=float, default=1.5, help="per-connection timeout (default 1.5)")
    scan.add_argument("--workers", type=int, default=200, help="concurrent connections (default 200)")
    scan.add_argument("-Pn", "--skip-discovery", action="store_true", help="treat every host as up")
    scan.add_argument("--no-banner", action="store_true", help="do not grab service banners")

    intel = parser.add_argument_group("vulnerability intelligence")
    intel.add_argument("--no-cve", action="store_true", help="disable CVE lookups")
    intel.add_argument("--online", action="store_true", help="also query the live NVD API")
    intel.add_argument("--cve-db", metavar="FILE", help="path to an alternate offline CVE database")

    out = parser.add_argument_group("output")
    out.add_argument("--html", metavar="FILE", help="write an HTML report")
    out.add_argument("--pdf", metavar="FILE", help="write a PDF report")
    out.add_argument("--json", metavar="FILE", help="write a JSON report")
    out.add_argument("-o", "--output", metavar="BASE", help="write BASE.html, BASE.pdf and BASE.json")
    out.add_argument("-q", "--quiet", action="store_true", help="suppress the console report")
    out.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low",
                     help="exit non-zero only if a finding at or above this severity exists")
    out.add_argument("--fail-on-finding", action="store_true",
                     help="exit non-zero when qualifying findings are present")
    return parser


def _select_ports(args) -> List[int]:
    if args.ports:
        return parse_ports(args.ports)
    if args.top:
        return list(TOP_PORTS[: args.top])
    return list(TOP_PORTS)


def _progress(host: str, done: int, total: int) -> None:
    sys.stderr.write(f"\r  scanning {host}: {done}/{total} ports")
    sys.stderr.flush()
    if done >= total:
        sys.stderr.write("\n")


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.targets:
        build_parser().error("provide at least one target")

    print(BANNER, file=sys.stderr)

    cve_db = None
    if not args.no_cve:
        try:
            cve_db = CVEDatabase.load(path=args.cve_db, online=args.online)
        except (OSError, ValueError) as exc:
            print(f"could not load CVE database: {exc}", file=sys.stderr)
            return 2

    scanner = VulnScanner(
        ports=_select_ports(args),
        timeout=args.timeout,
        workers=args.workers,
        grab_banners=not args.no_banner,
        cve_db=cve_db,
        skip_discovery=args.skip_discovery,
    )

    progress = None if args.quiet else _progress
    report = scanner.run(args.targets, progress=progress)

    if not args.quiet:
        print("\n".join(render_text(report)))

    if args.output:
        write_html(report, args.output + ".html")
        write_pdf(report, args.output + ".pdf")
        write_json(report, args.output + ".json")
        print(f"wrote {args.output}.html, {args.output}.pdf and {args.output}.json", file=sys.stderr)
    if args.html:
        write_html(report, args.html)
        print(f"wrote {args.html}", file=sys.stderr)
    if args.pdf:
        write_pdf(report, args.pdf)
        print(f"wrote {args.pdf}", file=sys.stderr)
    if args.json:
        write_json(report, args.json)
        print(f"wrote {args.json}", file=sys.stderr)

    threshold = SEVERITY_ORDER[args.min_severity]
    worst = max((SEVERITY_ORDER.get(v.severity, 0) for v in report.all_vulnerabilities), default=0)
    if args.fail_on_finding and worst >= threshold and worst > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
