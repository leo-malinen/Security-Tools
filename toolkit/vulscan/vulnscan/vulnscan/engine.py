from __future__ import annotations

import time
from typing import Callable, List, Optional

from .banners import grab_banner
from .cve import CVEDatabase
from .discovery import expand_targets, host_is_up, resolve
from .models import HostResult, PortResult, ScanReport
from .scanner import scan_ports
from .services import classify
from .versions import cpe_for, is_outdated


class VulnScanner:
    def __init__(
        self,
        ports: List[int],
        timeout: float = 1.5,
        workers: int = 200,
        grab_banners: bool = True,
        cve_db: Optional[CVEDatabase] = None,
        skip_discovery: bool = False,
    ):
        self.ports = list(ports)
        self.timeout = timeout
        self.workers = workers
        self.grab_banners = grab_banners
        self.cve_db = cve_db
        self.skip_discovery = skip_discovery

    def scan_host(self, host: str, progress: Optional[Callable[[int, int], None]] = None) -> HostResult:
        started = time.time()
        result = HostResult(host=host, hostname=resolve(host), started=started)
        if not self.skip_discovery and not host_is_up(host, timeout=min(self.timeout, 1.0)):
            result.alive = False
            result.finished = time.time()
            return result
        result.alive = True
        open_ports = scan_ports(host, self.ports, self.timeout, self.workers, progress)
        for port in open_ports:
            self._enrich(host, port)
        result.ports = open_ports
        result.finished = time.time()
        return result

    def _enrich(self, host: str, port: PortResult) -> None:
        banner = None
        if self.grab_banners:
            banner = grab_banner(host, port.port, self.timeout)
            port.banner = banner
        service, product, version = classify(port.port, banner)
        port.service = service
        port.product = product
        port.version = version
        if product:
            outdated, latest = is_outdated(product, version)
            port.outdated = outdated
            port.latest_version = latest
            port.cpe = cpe_for(product, version)
        if self.cve_db and product:
            port.vulnerabilities = self.cve_db.lookup(product, version)

    def run(self, targets, progress: Optional[Callable[[str, int, int], None]] = None) -> ScanReport:
        hosts = expand_targets(targets)
        report = ScanReport(
            targets=hosts,
            started=time.time(),
            config={
                "ports": len(self.ports),
                "timeout": self.timeout,
                "workers": self.workers,
                "banners": self.grab_banners,
                "cve": self.cve_db is not None,
                "skip_discovery": self.skip_discovery,
            },
        )
        for host in hosts:
            per_host = None
            if progress is not None:
                per_host = lambda done, total, h=host: progress(h, done, total)
            report.hosts.append(self.scan_host(host, per_host))
        report.finished = time.time()
        return report
