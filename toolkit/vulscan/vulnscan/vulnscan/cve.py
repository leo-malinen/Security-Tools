from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Dict, List, Optional

from .models import Vulnerability, severity_from_cvss
from .versions import satisfies

_DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "cve_db.json")
NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVEDatabase:
    def __init__(self, entries: Optional[Dict[str, list]] = None, online: bool = False, timeout: float = 6.0):
        self.entries = entries or {}
        self.online = online
        self.timeout = timeout

    @classmethod
    def load(cls, path: Optional[str] = None, online: bool = False) -> "CVEDatabase":
        path = path or _DATA_PATH
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
        products = {key.lower(): value for key, value in raw.get("products", {}).items()}
        return cls(entries=products, online=online)

    def lookup(self, product: Optional[str], version: Optional[str]) -> List[Vulnerability]:
        results: List[Vulnerability] = []
        if product:
            for record in self.entries.get(product.lower(), []):
                affected = record.get("affected", "")
                if version is None or not affected or satisfies(version, affected):
                    results.append(self._to_vuln(record))
        if self.online and product and version:
            results.extend(self._lookup_online(product, version))
        results.sort(key=lambda vuln: vuln.cvss, reverse=True)
        return _dedupe(results)

    def _to_vuln(self, record: Dict[str, object]) -> Vulnerability:
        cvss = float(record.get("cvss", 0.0) or 0.0)
        severity = str(record.get("severity") or severity_from_cvss(cvss))
        return Vulnerability(
            cve_id=str(record.get("cve", "")),
            severity=severity,
            cvss=cvss,
            summary=str(record.get("summary", "")),
            affected=str(record.get("affected", "")),
            fixed_version=record.get("fixed"),
            references=list(record.get("references", []) or []),
        )

    def _lookup_online(self, product: str, version: str) -> List[Vulnerability]:
        query = urllib.parse.urlencode({"keywordSearch": f"{product} {version}", "resultsPerPage": 20})
        request = urllib.request.Request(f"{NVD_ENDPOINT}?{query}", headers={"User-Agent": "vulnscan/1.0"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.load(response)
        except Exception:
            return []
        out: List[Vulnerability] = []
        for item in payload.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            summary = ""
            for description in cve.get("descriptions", []):
                if description.get("lang") == "en":
                    summary = description.get("value", "")
                    break
            cvss, severity = _extract_metric(cve.get("metrics", {}))
            out.append(
                Vulnerability(
                    cve_id=cve_id,
                    severity=severity,
                    cvss=cvss,
                    summary=summary,
                    affected=f"{product} {version}",
                    fixed_version=None,
                    references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"] if cve_id else [],
                )
            )
        return out


def _extract_metric(metrics: Dict[str, object]):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            score = float(data.get("baseScore", 0.0) or 0.0)
            return score, severity_from_cvss(score)
    return 0.0, "none"


def _dedupe(vulns: List[Vulnerability]) -> List[Vulnerability]:
    seen = set()
    out: List[Vulnerability] = []
    for vuln in vulns:
        if vuln.cve_id in seen:
            continue
        seen.add(vuln.cve_id)
        out.append(vuln)
    return out
