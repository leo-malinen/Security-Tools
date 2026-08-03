from __future__ import annotations

from typing import Optional, Tuple

from .versions import identify_product

PORT_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    69: "tftp",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    514: "syslog",
    587: "submission",
    631: "ipp",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1433: "ms-sql",
    1521: "oracle",
    1723: "pptp",
    2049: "nfs",
    2375: "docker",
    3306: "mysql",
    3389: "rdp",
    5060: "sip",
    5432: "postgresql",
    5900: "vnc",
    5985: "winrm",
    6379: "redis",
    6667: "irc",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465,
    587, 631, 993, 995, 1433, 1521, 2049, 2375, 3306, 3389, 5432, 5900, 5985,
    6379, 8000, 8080, 8443, 8888, 9200, 11211, 27017,
]


def service_for_port(port: int) -> Optional[str]:
    return PORT_SERVICES.get(port)


def classify(port: int, banner: Optional[str]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    service, product, version = identify_product(banner or "")
    if service is None:
        service = service_for_port(port)
    return service, product, version
