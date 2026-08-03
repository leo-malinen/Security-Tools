# vulnscan

A pure Python standard-library vulnerability scanner: port discovery, TCP port scanning, service detection, banner grabbing, outdated-software identification, CVE lookups, and HTML / PDF / JSON reporting.

**Authorized testing only.** Only scan hosts and networks you own or have explicit written permission to assess.

## Features

| # | Feature | Where |
|---|---------|-------|
| 1 | Discovers ports and live hosts (CIDR, ranges, TCP ping) | `vulnscan/discovery.py` |
| 2 | Scans ports (threaded TCP connect scan) | `vulnscan/scanner.py` |
| 3 | Detects services (port map + banner signatures) | `vulnscan/services.py` |
| 4 | Grabs banners (protocol probes, TLS wrapping) | `vulnscan/banners.py` |
| 5 | Identifies outdated software (version compare vs latest) | `vulnscan/versions.py` |
| 6 | Generates HTML / PDF / JSON reports | `vulnscan/report.py` |
| 7 | CVE lookups (offline database + optional live NVD) | `vulnscan/cve.py` |

## Requirements

Python 3.9+. No third-party packages are needed; the PDF writer is built in.

## Usage

```bash
python3 -m vulnscan 192.168.1.10
python3 -m vulnscan 10.0.0.0/24 --top 20 --html report.html
python3 -m vulnscan 192.168.1.5-20 -p 1-1024 -o report
python3 -m vulnscan example.local -Pn --online --pdf report.pdf
```

Windows PowerShell:

```powershell
python -m vulnscan 192.168.1.10 -o report
.\run.ps1 192.168.1.0/24 --top 20
```

### Key options

- `-p/--ports` explicit ports (`22,80,443` or `1-1024`)
- `--top N` scan the top N common ports
- `-Pn/--skip-discovery` treat every host as up
- `--no-banner` skip banner grabbing
- `--no-cve` disable CVE matching, `--online` also query the live NVD API
- `--html`, `--pdf`, `--json`, or `-o BASE` for all three
- `--fail-on-finding --min-severity high` for CI pipelines

## Try it safely

```bash
python3 tools/mock_target.py
python3 -m vulnscan 127.0.0.1 -Pn -p 2121,2222,8081,2525,8082 -o mock-report
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Notes

- The scan is a TCP connect scan, so no root/administrator privileges are required.
- The bundled CVE database is a curated sample for demonstration; use `--online` for live NVD data.
- Version-range matching is heuristic. Always verify findings before acting on them.
