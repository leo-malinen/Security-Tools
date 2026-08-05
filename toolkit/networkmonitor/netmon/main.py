import argparse
import signal
import sys
import time

from netmon.alerts import Alerter
from netmon.capture import AuthLogTailer, PacketSniffer
from netmon.config import load_config
from netmon.detectors import DetectionEngine
from netmon.storage import Storage


def build(args):
    config = load_config(args.config)
    storage = Storage(config.get("database", "netmon.db"))
    alerter = Alerter(storage, config)
    engine = DetectionEngine(storage, config, alerter)
    return config, storage, alerter, engine


def cmd_init(args):
    config, storage, _, _ = build(args)
    print("initialized database at %s" % config.get("database", "netmon.db"))
    storage.close()


def cmd_run(args):
    config, storage, _, engine = build(args)
    workers = []
    if not args.no_capture:
        sniffer = PacketSniffer(storage)
        sniffer.start()
        workers.append(sniffer)
        log_path = config.get("capture.log_file")
        if log_path:
            tailer = AuthLogTailer(storage, log_path, config.get("capture.poll_interval", 2))
            tailer.start()
            workers.append(tailer)

    running = {"value": True}

    def shutdown(signum, frame):
        running["value"] = False

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    interval = args.interval
    print("monitoring started, detection interval %ss" % interval, flush=True)
    while running["value"]:
        try:
            engine.run_cycle()
        except Exception as error:
            print("detection cycle failed: %s" % error, file=sys.stderr, flush=True)
        for _ in range(int(interval * 10)):
            if not running["value"]:
                break
            time.sleep(0.1)

    for worker in workers:
        worker.stop()
    storage.purge(args.retention_days)
    storage.close()
    print("monitoring stopped", flush=True)


def cmd_scan_once(args):
    _, storage, _, engine = build(args)
    findings = engine.run_cycle()
    for finding in findings:
        print("%s | %s | %s" % (finding["severity"].upper(), finding["kind"], finding["title"]))
    print("%d finding(s)" % len(findings))
    storage.close()


def cmd_feeds(args):
    from netmon.feeds.runner import mark_refreshed, run_feed_refresh

    config, storage, _, _ = build(args)
    sources = config.get("threat_feeds.sources", []) or []
    database = config.get("database", "netmon.db")
    storage.close()
    run_feed_refresh(database, sources)
    storage = Storage(database)
    mark_refreshed(storage)
    total = storage.one("SELECT COUNT(*) AS total FROM blocklist")
    print("blocklist entries: %s" % total["total"])
    storage.close()


def cmd_report(args):
    _, storage, _, _ = build(args)
    since = time.time() - args.hours * 3600
    rows = storage.query(
        "SELECT kind, severity, COUNT(*) AS total FROM alerts WHERE ts >= ?"
        " GROUP BY kind, severity ORDER BY total DESC",
        (since,),
    )
    print("alerts in last %dh" % args.hours)
    for row in rows:
        print("  %-14s %-8s %d" % (row["kind"], row["severity"], row["total"]))
    top = storage.query(
        "SELECT ip, score, blocklisted FROM ip_reputation ORDER BY score DESC LIMIT 10"
    )
    print("top suspicious ips")
    for row in top:
        print("  %-18s score=%-4d blocklisted=%s" % (row["ip"], row["score"], bool(row["blocklisted"])))
    storage.close()


def cmd_simulate(args):
    from netmon import simulate

    _, storage, _, engine = build(args)
    simulate.seed_all(storage)
    findings = engine.run_cycle()
    print("simulated traffic seeded, %d finding(s)" % len(findings))
    storage.close()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="netmon", description="network monitoring system")
    parser.add_argument("-c", "--config", default="config.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init").set_defaults(func=cmd_init)

    run = sub.add_parser("run")
    run.add_argument("--interval", type=float, default=15.0)
    run.add_argument("--retention-days", type=int, default=7)
    run.add_argument("--no-capture", action="store_true")
    run.set_defaults(func=cmd_run)

    sub.add_parser("scan-once").set_defaults(func=cmd_scan_once)
    sub.add_parser("feeds").set_defaults(func=cmd_feeds)
    sub.add_parser("simulate").set_defaults(func=cmd_simulate)

    report = sub.add_parser("report")
    report.add_argument("--hours", type=int, default=24)
    report.set_defaults(func=cmd_report)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
