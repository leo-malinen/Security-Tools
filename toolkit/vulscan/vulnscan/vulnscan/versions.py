from __future__ import annotations

import re
from typing import List, Optional, Tuple

_TOKEN_RE = re.compile(r"[0-9]+|[a-z]+")

SIGNATURES = [
    ("ssh", "OpenSSH", re.compile(r"OpenSSH[_/ ]([0-9][0-9a-zA-Z._]*)", re.I)),
    ("ssh", "Dropbear", re.compile(r"dropbear[_/ ]([0-9][0-9a-zA-Z._]*)", re.I)),
    ("http", "Apache httpd", re.compile(r"Apache/([0-9][0-9a-zA-Z._]*)", re.I)),
    ("http", "nginx", re.compile(r"nginx/([0-9][0-9a-zA-Z._]*)", re.I)),
    ("http", "Microsoft-IIS", re.compile(r"Microsoft-IIS/([0-9][0-9.]*)", re.I)),
    ("http", "lighttpd", re.compile(r"lighttpd/([0-9][0-9a-zA-Z._]*)", re.I)),
    ("http", "Jetty", re.compile(r"Jetty\(([0-9][0-9a-zA-Z._]*)", re.I)),
    ("ftp", "vsftpd", re.compile(r"vsftpd ([0-9][0-9a-zA-Z._]*)", re.I)),
    ("ftp", "ProFTPD", re.compile(r"ProFTPD ([0-9][0-9a-zA-Z._]*)", re.I)),
    ("ftp", "Pure-FTPd", re.compile(r"Pure-FTPd", re.I)),
    ("ftp", "FileZilla", re.compile(r"FileZilla Server ([0-9][0-9a-zA-Z._]*)", re.I)),
    ("smtp", "Exim", re.compile(r"Exim ([0-9][0-9a-zA-Z._]*)", re.I)),
    ("smtp", "Postfix", re.compile(r"Postfix", re.I)),
    ("smtp", "Sendmail", re.compile(r"Sendmail ([0-9][0-9a-zA-Z._/]*)", re.I)),
    ("mysql", "MariaDB", re.compile(r"([0-9][0-9a-zA-Z._]*)-MariaDB", re.I)),
    ("mysql", "MySQL", re.compile(r"([0-9]+\.[0-9]+\.[0-9][0-9a-zA-Z._]*)", re.I)),
    ("smb", "Samba", re.compile(r"Samba ([0-9][0-9a-zA-Z._]*)", re.I)),
    ("pop3", "Dovecot", re.compile(r"Dovecot", re.I)),
    ("redis", "Redis", re.compile(r"redis_version:([0-9][0-9a-zA-Z._]*)", re.I)),
    ("memcached", "Memcached", re.compile(r"VERSION ([0-9][0-9a-zA-Z._]*)", re.I)),
    ("ssl", "OpenSSL", re.compile(r"OpenSSL/([0-9][0-9a-zA-Z._]*)", re.I)),
]

LATEST_VERSIONS = {
    "openssh": "9.8p1",
    "dropbear": "2022.83",
    "apache httpd": "2.4.62",
    "nginx": "1.27.1",
    "microsoft-iis": "10.0",
    "lighttpd": "1.4.76",
    "vsftpd": "3.0.5",
    "proftpd": "1.3.8",
    "exim": "4.98",
    "sendmail": "8.18.1",
    "mysql": "8.4.2",
    "mariadb": "11.4.3",
    "samba": "4.20.2",
    "redis": "7.4.0",
    "memcached": "1.6.31",
    "openssl": "3.3.2",
}


def version_key(version: str) -> List[Tuple[int, int, str]]:
    key: List[Tuple[int, int, str]] = []
    for token in _TOKEN_RE.findall(version.lower()):
        if token.isdigit():
            key.append((1, int(token), ""))
        else:
            key.append((0, 0, token))
    return key


def compare_versions(left: str, right: str) -> int:
    a = version_key(left)
    b = version_key(right)
    for x, y in zip(a, b):
        if x < y:
            return -1
        if x > y:
            return 1
    if len(a) < len(b):
        return -1
    if len(a) > len(b):
        return 1
    return 0


def _parse_constraint(part: str) -> Tuple[str, str]:
    for op in ("<=", ">=", "==", "!=", "<", ">", "="):
        if part.startswith(op):
            return op, part[len(op):].strip()
    return "==", part


def satisfies(version: str, constraint: str) -> bool:
    version = (version or "").strip()
    if not version or not constraint:
        return bool(version) and not constraint
    for part in constraint.replace(",", " ").split():
        op, target = _parse_constraint(part)
        if not target:
            continue
        result = compare_versions(version, target)
        if op in ("==", "=") and result != 0:
            return False
        if op == "!=" and result == 0:
            return False
        if op == "<" and not result < 0:
            return False
        if op == "<=" and not result <= 0:
            return False
        if op == ">" and not result > 0:
            return False
        if op == ">=" and not result >= 0:
            return False
    return True


def identify_product(banner: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    if not banner:
        return None, None, None
    for service, product, pattern in SIGNATURES:
        match = pattern.search(banner)
        if match:
            version = match.group(1) if match.groups() else None
            return service, product, version
    return None, None, None


def latest_for(product: Optional[str]) -> Optional[str]:
    if not product:
        return None
    return LATEST_VERSIONS.get(product.lower())


def is_outdated(product: Optional[str], version: Optional[str]) -> Tuple[bool, Optional[str]]:
    latest = latest_for(product)
    if not latest or not version:
        return False, latest
    try:
        return compare_versions(version, latest) < 0, latest
    except (TypeError, ValueError):
        return False, latest


def cpe_for(product: Optional[str], version: Optional[str]) -> Optional[str]:
    if not product:
        return None
    vendor = product.lower().replace(" ", "_").replace("-", "_")
    version_part = version or "*"
    return f"cpe:2.3:a:{vendor}:{vendor}:{version_part}:*:*:*:*:*:*:*"
