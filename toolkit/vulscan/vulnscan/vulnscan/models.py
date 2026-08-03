from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


@dataclass
class Vulnerability:
    cve_id: str
    severity: str
    cvss: float
    summary: str
    affected: str
    fixed_version: Optional[str] = None
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "cve_id": self.cve_id,
            "severity": self.severity,
            "cvss": self.cvss,
            "summary": self.summary,
            "affected": self.affected,
            "fixed_version": self.fixed_version,
            "references": list(self.references),
        }


@dataclass
class PortResult:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    latest_version: Optional[str] = None
    outdated: bool = False
    cpe: Optional[str] = None
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    @property
    def service_label(self) -> str:
        if self.product and self.version:
            return f"{self.product} {self.version}"
        if self.product:
            return self.product
        return self.service or "unknown"

    @property
    def max_cvss(self) -> float:
        return max((v.cvss for v in self.vulnerabilities), default=0.0)

    @property
    def risk(self) -> str:
        return severity_from_cvss(self.max_cvss)

    def to_dict(self) -> Dict[str, object]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "banner": self.banner,
            "latest_version": self.latest_version,
            "outdated": self.outdated,
            "cpe": self.cpe,
            "risk": self.risk,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }


@dataclass
class HostResult:
    host: str
    hostname: Optional[str] = None
    alive: bool = False
    ports: List[PortResult] = field(default_factory=list)
    started: float = 0.0
    finished: float = 0.0

    @property
    def open_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.state == "open"]

    @property
    def vulnerabilities(self) -> List[Vulnerability]:
        out: List[Vulnerability] = []
        for port in self.ports:
            out.extend(port.vulnerabilities)
        return out

    @property
    def max_cvss(self) -> float:
        return max((p.max_cvss for p in self.ports), default=0.0)

    @property
    def risk(self) -> str:
        return severity_from_cvss(self.max_cvss)

    @property
    def duration(self) -> float:
        return max(0.0, self.finished - self.started)

    def to_dict(self) -> Dict[str, object]:
        return {
            "host": self.host,
            "hostname": self.hostname,
            "alive": self.alive,
            "risk": self.risk,
            "duration": round(self.duration, 3),
            "ports": [p.to_dict() for p in self.ports],
        }


@dataclass
class ScanReport:
    targets: List[str]
    hosts: List[HostResult] = field(default_factory=list)
    started: float = 0.0
    finished: float = 0.0
    config: Dict[str, object] = field(default_factory=dict)

    @property
    def hosts_up(self) -> List[HostResult]:
        return [h for h in self.hosts if h.alive]

    @property
    def all_vulnerabilities(self) -> List[Vulnerability]:
        out: List[Vulnerability] = []
        for host in self.hosts:
            out.extend(host.vulnerabilities)
        return out

    @property
    def duration(self) -> float:
        return max(0.0, self.finished - self.started)

    def severity_counts(self) -> Dict[str, int]:
        counts = {name: 0 for name in SEVERITY_ORDER}
        for vuln in self.all_vulnerabilities:
            counts[vuln.severity] = counts.get(vuln.severity, 0) + 1
        return counts

    def to_dict(self) -> Dict[str, object]:
        return {
            "targets": list(self.targets),
            "started": self.started,
            "finished": self.finished,
            "duration": round(self.duration, 3),
            "config": dict(self.config),
            "severity_counts": self.severity_counts(),
            "hosts": [h.to_dict() for h in self.hosts],
        }
