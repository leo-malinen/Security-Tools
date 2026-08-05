# netmon

A simple Python network monitoring system with SQLite storage, Scrapy-based threat feed ingestion, and Grafana dashboards.

## Detections

| Detection | Signal | Default threshold |
| --- | --- | --- |
| Port scan | distinct destination ports per source IP | 15 ports / 60s |
| Brute force | failed auth events per source IP | 8 failures / 300s |
| Traffic spike | packets per window vs rolling baseline | mean + 3 stddev |
| Suspicious IP | reputation score from behavior + threat feeds | score >= 50 |

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python -m netmon.main init
python -m netmon.main simulate          # seed demo data and run detections
python -m netmon.main scan-once         # run one detection cycle
sudo python -m netmon.main run          # live capture + continuous detection
python -m netmon.main run --no-capture  # detection only, no root needed
python -m netmon.main feeds             # refresh blocklists with Scrapy
python -m netmon.main report --hours 24
```

Live packet capture uses a raw socket and requires root. The auth log tailer reads
`capture.log_file` (default `/var/log/auth.log`) for failed and accepted logins.

## Scrapy threat feeds

`netmon/feeds` is a Scrapy project. The `blocklist` spider parses plain-text IP lists,
the `threatpage` spider extracts IPs from HTML pages. Results are written to the
`blocklist` table by the SQLite pipeline.

```bash
scrapy crawl blocklist -a urls="https://lists.blocklist.de/lists/ssh.txt"
```

Configure sources under `threat_feeds.sources` in `config.yaml`.

## Alerts

Alerts are written to the `alerts` table and delivered via console, JSON lines file,
webhook (Slack/Discord/generic), and SMTP email. Severity filtering and per
IP/type cooldowns are set under `alerts` in `config.yaml`.

## Grafana

1. Install the SQLite datasource plugin:
   `grafana-cli plugins install frser-sqlite-datasource`
2. Provision the datasource with `grafana/datasource.yaml` (update `path` to your db).
3. Import `grafana/dashboard.json`.

Panels: alert counts, suspicious IP count, blocklist hits, failed logins, packet volume
timeseries, alerts by type, top suspicious IPs, recent alerts.

## Schema

`packets`, `auth_events`, `alerts`, `ip_reputation`, `blocklist`, `traffic_windows`, `state`.

## Note

Monitor only networks you own or are authorized to monitor.
