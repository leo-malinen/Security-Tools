from __future__ import annotations

import html
import json
import time
from typing import List, Optional

from .models import ScanReport

BACKSLASH = chr(92)

SEVERITY_COLORS = {
    "critical": "#b71c1c",
    "high": "#e64a19",
    "medium": "#f9a825",
    "low": "#2e7d32",
    "none": "#607d8b",
    "unknown": "#607d8b",
}


def _fmt_time(value: float) -> str:
    if not value:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value))


def render_text(report: ScanReport) -> List[str]:
    lines: List[str] = []
    lines.append("vulnscan report")
    lines.append("=" * 60)
    lines.append(f"targets    : {', '.join(report.targets)}")
    lines.append(f"started    : {_fmt_time(report.started)}")
    lines.append(f"finished   : {_fmt_time(report.finished)}")
    lines.append(f"duration   : {report.duration:.1f}s")
    lines.append(f"hosts up   : {len(report.hosts_up)} / {len(report.hosts)}")
    counts = report.severity_counts()
    lines.append(
        "findings   : "
        + ", ".join(
            f"{name}={counts[name]}" for name in ("critical", "high", "medium", "low") if counts.get(name)
        )
        or "findings   : none"
    )
    lines.append("")

    for host in report.hosts:
        header = host.host
        if host.hostname:
            header += f" ({host.hostname})"
        lines.append(header)
        lines.append("-" * 60)
        if not host.alive:
            lines.append("  host down or unreachable")
            lines.append("")
            continue
        if not host.open_ports:
            lines.append("  no open ports found")
            lines.append("")
            continue
        lines.append("  PORT      SERVICE        PRODUCT/VERSION            NOTES")
        for port in host.open_ports:
            note = ""
            if port.outdated and port.latest_version:
                note = f"outdated (latest {port.latest_version})"
            product = port.service_label
            lines.append(
                "  {port:<9} {service:<14} {product:<26} {note}".format(
                    port=f"{port.port}/{port.protocol}",
                    service=(port.service or "-")[:14],
                    product=product[:26],
                    note=note,
                )
            )
            if port.banner:
                lines.append(f"      banner: {port.banner.splitlines()[0][:70]}")
            for vuln in port.vulnerabilities:
                fixed = f" fixed in {vuln.fixed_version}" if vuln.fixed_version else ""
                lines.append(
                    f"      [{vuln.severity.upper()}] {vuln.cve_id} (CVSS {vuln.cvss}){fixed}"
                )
                lines.append(f"          {vuln.summary[:74]}")
        lines.append("")
    return lines


def render_html(report: ScanReport) -> str:
    counts = report.severity_counts()
    css = (
        "body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;"
        "margin:0;background:#0f1117;color:#e6e8eb;}"
        ".wrap{max-width:1000px;margin:0 auto;padding:32px;}"
        "h1{font-size:24px;margin:0 0 4px;}"
        ".muted{color:#98a2b3;font-size:13px;}"
        ".cards{display:flex;gap:12px;margin:20px 0;flex-wrap:wrap;}"
        ".card{background:#171a21;border:1px solid #242832;border-radius:10px;padding:14px 18px;min-width:110px;}"
        ".card .n{font-size:22px;font-weight:700;}"
        ".host{background:#171a21;border:1px solid #242832;border-radius:12px;padding:18px 20px;margin:16px 0;}"
        ".host h2{margin:0 0 10px;font-size:18px;}"
        "table{width:100%;border-collapse:collapse;font-size:13px;}"
        "th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #242832;vertical-align:top;}"
        "th{color:#98a2b3;font-weight:600;}"
        ".pill{display:inline-block;padding:2px 8px;border-radius:20px;color:#fff;font-size:11px;font-weight:700;text-transform:uppercase;}"
        ".banner{font-family:ui-monospace,Menlo,Consolas,monospace;color:#9aa4b2;font-size:12px;}"
        ".cve{margin:6px 0;padding:8px 10px;background:#12151c;border-left:3px solid #444;border-radius:6px;}"
        ".cve a{color:#7aa2f7;text-decoration:none;}"
        ".tag{display:inline-block;background:#2a2f3a;color:#f2b8b5;padding:1px 6px;border-radius:5px;font-size:11px;}"
        "footer{color:#667085;font-size:12px;margin-top:24px;}"
    )

    def pill(severity: str) -> str:
        color = SEVERITY_COLORS.get(severity, "#607d8b")
        return f'<span class="pill" style="background:{color}">{html.escape(severity)}</span>'

    parts: List[str] = []
    parts.append("<!doctype html><html><head><meta charset='utf-8'>")
    parts.append("<meta name='viewport' content='width=device-width,initial-scale=1'>")
    parts.append("<title>vulnscan report</title>")
    parts.append(f"<style>{css}</style></head><body><div class='wrap'>")
    parts.append("<h1>vulnscan report</h1>")
    parts.append(
        f"<div class='muted'>Targets: {html.escape(', '.join(report.targets))} &middot; "
        f"{_fmt_time(report.started)} &middot; {report.duration:.1f}s &middot; "
        f"{len(report.hosts_up)}/{len(report.hosts)} hosts up</div>"
    )

    parts.append("<div class='cards'>")
    for name in ("critical", "high", "medium", "low"):
        color = SEVERITY_COLORS[name]
        parts.append(
            f"<div class='card'><div class='n' style='color:{color}'>{counts.get(name, 0)}</div>"
            f"<div class='muted'>{name}</div></div>"
        )
    total_open = sum(len(h.open_ports) for h in report.hosts)
    parts.append(
        f"<div class='card'><div class='n'>{total_open}</div><div class='muted'>open ports</div></div>"
    )
    parts.append("</div>")

    for host in report.hosts:
        title = html.escape(host.host)
        if host.hostname:
            title += f" <span class='muted'>({html.escape(host.hostname)})</span>"
        parts.append("<div class='host'>")
        parts.append(f"<h2>{title} &nbsp; {pill(host.risk)}</h2>")
        if not host.alive:
            parts.append("<div class='muted'>Host down or unreachable.</div></div>")
            continue
        if not host.open_ports:
            parts.append("<div class='muted'>No open ports found.</div></div>")
            continue
        parts.append("<table><thead><tr><th>Port</th><th>Service</th><th>Product / Version</th>")
        parts.append("<th>Status</th><th>Findings</th></tr></thead><tbody>")
        for port in host.open_ports:
            status = "current"
            if port.outdated and port.latest_version:
                status = f"<span class='tag'>outdated</span> latest {html.escape(port.latest_version)}"
            findings = []
            if port.banner:
                findings.append(f"<div class='banner'>{html.escape(port.banner.splitlines()[0][:120])}</div>")
            for vuln in port.vulnerabilities:
                refs = ""
                if vuln.references:
                    refs = f" &middot; <a href='{html.escape(vuln.references[0])}'>details</a>"
                fixed = f" &middot; fixed in {html.escape(vuln.fixed_version)}" if vuln.fixed_version else ""
                findings.append(
                    f"<div class='cve'>{pill(vuln.severity)} <b>{html.escape(vuln.cve_id)}</b> "
                    f"(CVSS {vuln.cvss}){fixed}{refs}<br>{html.escape(vuln.summary)}</div>"
                )
            parts.append(
                "<tr><td>{port}/{proto}</td><td>{service}</td><td>{product}</td><td>{status}</td>"
                "<td>{findings}</td></tr>".format(
                    port=port.port,
                    proto=port.protocol,
                    service=html.escape(port.service or "-"),
                    product=html.escape(port.service_label),
                    status=status,
                    findings="".join(findings) or "<span class='muted'>none</span>",
                )
            )
        parts.append("</tbody></table></div>")

    parts.append(
        "<footer>Generated by vulnscan. Authorized testing only. "
        "Offline CVE matches are heuristic; verify before acting.</footer>"
    )
    parts.append("</div></body></html>")
    return "".join(parts)


def render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def _pdf_escape(text: str) -> str:
    text = text.replace(BACKSLASH, BACKSLASH + BACKSLASH)
    text = text.replace("(", BACKSLASH + "(")
    text = text.replace(")", BACKSLASH + ")")
    return text


def _content_stream(page_lines: List[str], size: int, leading: int, left: int, top: int) -> bytes:
    parts = [b"BT", ("/F1 %d Tf" % size).encode(), ("%d TL" % leading).encode(),
             ("%d %d Td" % (left, top)).encode()]
    for index, line in enumerate(page_lines):
        text = _pdf_escape(line[:110]).encode("latin-1", "replace")
        if index == 0:
            parts.append(b"(" + text + b") Tj")
        else:
            parts.append(b"T* (" + text + b") Tj")
    parts.append(b"ET")
    return b"\n".join(parts)


def build_pdf(lines: List[str]) -> bytes:
    size, leading, top, left, bottom = 9, 12, 760, 48, 48
    per_page = max(1, (top - bottom) // leading)
    pages = [lines[i:i + per_page] for i in range(0, len(lines), per_page)] or [[""]]

    font_id = 3
    objects = {1: b"<< /Type /Catalog /Pages 2 0 R >>",
               font_id: b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>"}
    next_id = 4
    page_ids: List[int] = []
    for page in pages:
        content_id = next_id
        page_id = next_id + 1
        next_id += 2
        stream = _content_stream(page, size, leading, left, top)
        objects[content_id] = b"<< /Length %d >>\nstream\n%s\nendstream" % (len(stream), stream)
        objects[page_id] = (
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            "/Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>"
            % (font_id, content_id)
        ).encode()
        page_ids.append(page_id)

    kids = " ".join("%d 0 R" % pid for pid in page_ids)
    objects[2] = ("<< /Type /Pages /Kids [%s] /Count %d >>" % (kids, len(page_ids))).encode()

    max_id = max(objects)
    out = bytearray(b"%PDF-1.4\n")
    offsets = {}
    for obj_id in range(1, max_id + 1):
        offsets[obj_id] = len(out)
        out += ("%d 0 obj\n" % obj_id).encode() + objects[obj_id] + b"\nendobj\n"

    xref_pos = len(out)
    out += ("xref\n0 %d\n" % (max_id + 1)).encode()
    out += b"0000000000 65535 f \n"
    for obj_id in range(1, max_id + 1):
        out += ("%010d 00000 n \n" % offsets[obj_id]).encode()
    out += ("trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (max_id + 1, xref_pos)).encode()
    return bytes(out)


def write_pdf(report: ScanReport, path: str) -> None:
    with open(path, "wb") as handle:
        handle.write(build_pdf(render_text(report)))


def write_html(report: ScanReport, path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render_html(report))


def write_json(report: ScanReport, path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render_json(report))
