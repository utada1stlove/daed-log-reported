#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import csv
import datetime as _dt
import html
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from zoneinfo import ZoneInfo

KV_RE = re.compile(r'(\w+)=(".*?"|\S+)')
MSG_RE = re.compile(r'(?P<src>.+?)\s+<->\s+(?P<dst>.+)$')

APP_RULES = [
    ("TikTok", re.compile(r"(?:^|\.)tiktokv\.com$", re.I)),
    ("TikTok", re.compile(r"(?:^|\.)tiktok\.com$", re.I)),
    ("YouTube/Google", re.compile(r"(?:^|\.)youtube\.com$", re.I)),
    ("YouTube/Google", re.compile(r"(?:^|\.)ggpht\.com$", re.I)),
    ("YouTube/Google", re.compile(r"(?:^|\.)googleapis\.com$", re.I)),
    ("GitHub", re.compile(r"(?:^|\.)githubusercontent\.com$", re.I)),
    ("GitHub", re.compile(r"(?:^|\.)github\.com$", re.I)),
    ("Microsoft 365", re.compile(r"(?:^|\.)office365\.com$", re.I)),
    ("Microsoft 365", re.compile(r"(?:^|\.)outlook\.office365\.com$", re.I)),
    ("Twitch", re.compile(r"(?:^|\.)twitch\.tv$", re.I)),
    ("JD.com", re.compile(r"(?:^|\.)jd\.com$", re.I)),
]

def unquote(v: str) -> str:
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1]
    return v

def parse_logfmt_line(line: str) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for k, v in KV_RE.findall(line):
        fields[k] = unquote(v)
    return fields

def parse_msg_endpoints(msg: str) -> Tuple[Optional[str], Optional[str]]:
    m = MSG_RE.search(msg or "")
    if not m:
        return None, None
    return m.group("src").strip(), m.group("dst").strip()

def split_host_port(endpoint: str) -> Tuple[str, str]:
    if not endpoint:
        return "", ""
    ep = endpoint.strip()
    if ep.startswith("[") and "]" in ep:
        rb = ep.find("]")
        host = ep[1:rb]
        rest = ep[rb + 1 :]
        if rest.startswith(":"):
            return host, rest[1:]
        return host, ""
    if ":" in ep:
        host, port = ep.rsplit(":", 1)
        if port.isdigit():
            return host, port
        return ep, ""
    return ep, ""

def parse_daed_time(t: str, default_year: int, log_tz: ZoneInfo) -> Optional[_dt.datetime]:
    if not t:
        return None
    try:
        dt_naive = _dt.datetime.strptime(f"{default_year} {t}", "%Y %b %d %H:%M:%S")
        return dt_naive.replace(tzinfo=log_tz)
    except Exception:
        return None

def classify_app(domain: str) -> str:
    d = (domain or "").strip().lower()
    if not d:
        return "Unknown"
    for name, pat in APP_RULES:
        if pat.search(d):
            return name
    return "Other"

def classify_log_type(fields: Dict[str, str]) -> str:
    msg = fields.get("msg", "")
    if "<->" in msg:
        return "CONNECTION"
    level = (fields.get("level", "") or "").lower()
    if level in ("warning", "warn") and "<->" not in msg:
        return "INTERNAL_WARNING"
    return "OTHER"

def md_escape(s: str) -> str:
    return (s or "").replace("\n", " ").replace("\r", " ")

@dataclass
class ConnRecord:
    time_raw: str
    time_dt: Optional[_dt.datetime]  # aware datetime in log_tz
    level: str
    src_ep: str
    dst_ep: str
    src_host: str
    src_port: str
    dst_host: str
    dst_port: str
    sniffed: str
    ip: str
    mac: str
    network: str
    outbound: str
    dialer: str
    policy: str
    dscp: str
    pid: str
    pname: str
    raw_line: str

    @property
    def target_domain(self) -> str:
        return self.sniffed or self.dst_host

    @property
    def app(self) -> str:
        return classify_app(self.target_domain)

    @property
    def route_label(self) -> str:
        return self.outbound or "unknown"

    @property
    def policy_label(self) -> str:
        return self.policy or "unknown"

def fields_to_conn(fields: Dict[str, str], raw_line: str, log_tz: ZoneInfo) -> Optional[ConnRecord]:
    msg = fields.get("msg", "")
    src_ep, dst_ep = parse_msg_endpoints(msg)
    if not src_ep or not dst_ep:
        return None

    src_host, src_port = split_host_port(src_ep)
    dst_host, dst_port = split_host_port(dst_ep)

    time_raw = fields.get("time", "")
    default_year = _dt.datetime.now(tz=ZoneInfo("UTC")).year
    time_dt = parse_daed_time(time_raw, default_year=default_year, log_tz=log_tz)

    return ConnRecord(
        time_raw=time_raw,
        time_dt=time_dt,
        level=fields.get("level", ""),
        src_ep=src_ep,
        dst_ep=dst_ep,
        src_host=src_host,
        src_port=src_port,
        dst_host=dst_host,
        dst_port=dst_port,
        sniffed=fields.get("sniffed", ""),
        ip=fields.get("ip", ""),
        mac=fields.get("mac", ""),
        network=fields.get("network", ""),
        outbound=fields.get("outbound", ""),
        dialer=fields.get("dialer", ""),
        policy=fields.get("policy", ""),
        dscp=fields.get("dscp", ""),
        pid=fields.get("pid", ""),
        pname=(fields.get("pname", "") or "").strip(),
        raw_line=raw_line.rstrip("\n"),
    )

def fmt_dt(dt: Optional[_dt.datetime], display_tz: ZoneInfo) -> str:
    if not dt:
        return "N/A"
    return dt.astimezone(display_tz).strftime("%Y-%m-%d %H:%M:%S")

def fmt_time_hms(dt: Optional[_dt.datetime], display_tz: ZoneInfo, fallback_raw: str) -> str:
    if not dt:
        return fallback_raw or "N/A"
    return dt.astimezone(display_tz).strftime("%H:%M:%S")

def render_markdown(
    title: str,
    conns: List[ConnRecord],
    warnings: List[Dict[str, str]],
    top_n: int,
    log_tz_name: str,
    display_tz_name: str,
    display_tz: ZoneInfo,
) -> str:
    times = [c.time_dt for c in conns if c.time_dt is not None]
    t_min = min(times) if times else None
    t_max = max(times) if times else None

    by_outbound = Counter(c.route_label for c in conns)
    by_policy = Counter(c.policy_label for c in conns)
    by_network = Counter(c.network or "unknown" for c in conns)
    by_app = Counter(c.app for c in conns)
    by_domain = Counter((c.target_domain or "unknown") for c in conns)
    by_mac = Counter((c.mac or "unknown") for c in conns)
    by_srcip = Counter((c.src_host or "unknown") for c in conns)

    app_domains = defaultdict(set)
    app_outbounds = defaultdict(Counter)
    app_dialers = defaultdict(Counter)
    app_policies = defaultdict(Counter)
    for c in conns:
        app = c.app
        app_domains[app].add(c.target_domain or "unknown")
        app_outbounds[app][c.route_label] += 1
        app_dialers[app][c.dialer or "unknown"] += 1
        app_policies[app][c.policy_label] += 1

    lines: List[str] = []
    lines.append(f"# {md_escape(title)}")
    lines.append("")
    lines.append("## Overview")
    lines.append("")
    lines.append(f"- 日志时区：{md_escape(log_tz_name)}")
    lines.append(f"- 显示时区：{md_escape(display_tz_name)}")
    lines.append(f"- 时间范围：{fmt_dt(t_min, display_tz)} ~ {fmt_dt(t_max, display_tz)}")
    lines.append(f"- 连接日志条数（CONNECTION）：{len(conns)}")
    lines.append(f"- 内部告警条数（WARNING）：{len(warnings)}")
    lines.append(f"- 涉及内网源 IP 数：{len(by_srcip)}")
    lines.append(f"- 涉及设备 MAC 数：{len(by_mac)}")
    lines.append("")

    lines.append("## Traffic Summary")
    lines.append("")
    lines.append("### 出站类型分布（outbound）")
    for k, v in by_outbound.most_common():
        lines.append(f"- {md_escape(k)}：{v}")
    lines.append("")
    lines.append("### 策略类型（policy）")
    for k, v in by_policy.most_common():
        lines.append(f"- {md_escape(k)}：{v}")
    lines.append("")
    lines.append("### 网络类型（network）")
    for k, v in by_network.most_common():
        lines.append(f"- {md_escape(k)}：{v}")
    lines.append("")
    lines.append("### 应用分类（基于 sniffed/目标域名）")
    for k, v in by_app.most_common():
        lines.append(f"- {md_escape(k)}：{v}")
    lines.append("")

    lines.append(f"## Top Domains (Top {top_n})")
    lines.append("")
    for d, cnt in by_domain.most_common(top_n):
        lines.append(f"- {md_escape(d)}：{cnt}")
    lines.append("")

    lines.append("## Application & Domain Analysis")
    lines.append("")
    for app, _cnt in by_app.most_common():
        lines.append(f"### {md_escape(app)}")
        doms = sorted(app_domains[app])
        lines.append(f"- 域名（{len(doms)}）：")
        for d in doms:
            lines.append(f"  - {md_escape(d)}")
        lines.append(f"- 出站分布：{', '.join([f'{md_escape(k)}={v}' for k, v in app_outbounds[app].most_common()])}")
        lines.append(f"- 拨号器分布：{', '.join([f'{md_escape(k)}={v}' for k, v in app_dialers[app].most_common()])}")
        lines.append(f"- 策略分布：{', '.join([f'{md_escape(k)}={v}' for k, v in app_policies[app].most_common()])}")
        if len(app_outbounds[app]) >= 2:
            lines.append("- 提示：同一应用/域名族存在多种出站策略，可能是规则分流导致的差异（通常正常，但也可能暴露规则遗漏）。")
        lines.append("")

    if warnings:
        lines.append("## Warnings & Internal Messages")
        lines.append("")
        for w in warnings:
            time_raw = w.get("time", "")
            msg = w.get("msg", "")
            name = w.get("name", "")
            typ = w.get("type", "")
            lines.append(f"- {md_escape(time_raw)} {md_escape(msg)}")
            meta = []
            if name:
                meta.append(f"name={name}")
            if typ:
                meta.append(f"type={typ}")
            if meta:
                lines.append(f"  - 元信息：{', '.join(meta)}")
            lines.append("  - 影响：通常不影响转发与分流（多为 Web/GraphQL 层的类型转换告警）。")
        lines.append("")

    lines.append("## Automated Conclusions")
    lines.append("")
    if by_outbound:
        lines.append(f"- 出站总体以 `{md_escape(by_outbound.most_common(1)[0][0])}` 为主（共 {len(conns)} 条连接日志）。")
    if any(k != "fixed" for k in by_policy.keys()):
        dyn = [k for k in by_policy.keys() if k != "fixed"]
        lines.append(f"- 检测到动态策略决策：{', '.join([md_escape(x) for x in dyn])}（这类流量通常用于自动优选/质量策略）。")
    mixed_apps = [app for app in app_outbounds if len(app_outbounds[app]) >= 2 and app not in ("Unknown", "Other")]
    if mixed_apps:
        lines.append(f"- 存在同一应用族多出站策略：{', '.join([md_escape(x) for x in mixed_apps])}（建议确认是否符合预期的分流策略）。")
    sniff_miss = sum(1 for c in conns if not c.sniffed)
    if conns and sniff_miss:
        rate = sniff_miss / len(conns) * 100.0
        lines.append(f"- 未嗅探到域名的连接：{sniff_miss}/{len(conns)}（{rate:.1f}%）。")
    lines.append("")

    return "\n".join(lines)

def render_html(title: str, markdown_text: str) -> str:
    esc = html.escape(markdown_text)
    lines = esc.splitlines()

    out_lines: List[str] = []
    in_code = False
    for ln in lines:
        if ln.strip().startswith("```"):
            if not in_code:
                in_code = True
                out_lines.append("<pre><code>")
            else:
                in_code = False
                out_lines.append("</code></pre>")
            continue
        if in_code:
            out_lines.append(ln)
            continue

        if ln.startswith("# "):
            out_lines.append(f"<h1>{ln[2:].strip()}</h1>")
        elif ln.startswith("## "):
            out_lines.append(f"<h2>{ln[3:].strip()}</h2>")
        elif ln.startswith("### "):
            out_lines.append(f"<h3>{ln[4:].strip()}</h3>")
        elif ln.startswith("- "):
            out_lines.append(f"<li>{ln[2:].strip()}</li>")
        else:
            if ln.strip() == "":
                out_lines.append("")
            else:
                ln2 = re.sub(r"`([^`]+)`", r"<code>\1</code>", ln)
                out_lines.append(f"<p>{ln2}</p>")

    final_lines: List[str] = []
    i = 0
    while i < len(out_lines):
        if out_lines[i].startswith("<li>"):
            final_lines.append("<ul>")
            while i < len(out_lines) and out_lines[i].startswith("<li>"):
                final_lines.append(out_lines[i])
                i += 1
            final_lines.append("</ul>")
            continue
        final_lines.append(out_lines[i])
        i += 1

    css = """
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, "Noto Sans", "Liberation Sans", sans-serif;
           margin: 24px; line-height: 1.5; color: #111; }
    h1, h2, h3 { margin-top: 1.2em; }
    code { background: #f3f4f6; padding: 0.1em 0.3em; border-radius: 4px; }
    pre { background: #0b1020; color: #e5e7eb; padding: 14px; border-radius: 8px; overflow-x: auto; }
    pre code { background: transparent; padding: 0; }
    ul { margin: 0.2em 0 0.8em 1.2em; }
    p { margin: 0.2em 0 0.6em 0; }
    .footer { margin-top: 2em; font-size: 12px; color: #555; }
    """
    now = _dt.datetime.now(tz=ZoneInfo("UTC")).strftime("%Y-%m-%d %H:%M:%S UTC")
    body = "\n".join(final_lines)
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>{css}</style>
</head>
<body>
{body}
<div class="footer">Generated at {html.escape(now)} by daed-log-report.py</div>
</body>
</html>
"""

def write_csv(conns: List[ConnRecord], path: str, display_tz: ZoneInfo) -> None:
    """
    Export a flat table for spreadsheet analysis.
    """
    headers = [
        "time_display",          # YYYY-MM-DD HH:MM:SS in display_tz
        "time_raw",              # original daed time field
        "src_host",
        "src_port",
        "dst_host",
        "dst_port",
        "sniffed",
        "target_domain",
        "ip",
        "network",
        "outbound",
        "dialer",
        "policy",
        "dscp",
        "mac",
        "pid",
        "pname",
        "app",
        "raw_line",
    ]

    # sort by time
    def sort_key(c: ConnRecord):
        return (c.time_dt or _dt.datetime(1970, 1, 1, tzinfo=ZoneInfo("UTC")), c.src_ep, c.dst_ep)

    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for c in sorted(conns, key=sort_key):
            time_display = fmt_dt(c.time_dt, display_tz) if c.time_dt else "N/A"
            w.writerow({
                "time_display": time_display,
                "time_raw": c.time_raw,
                "src_host": c.src_host,
                "src_port": c.src_port,
                "dst_host": c.dst_host,
                "dst_port": c.dst_port,
                "sniffed": c.sniffed,
                "target_domain": c.target_domain,
                "ip": c.ip,
                "network": c.network,
                "outbound": c.route_label,
                "dialer": c.dialer,
                "policy": c.policy_label,
                "dscp": c.dscp,
                "mac": c.mac,
                "pid": c.pid,
                "pname": c.pname,
                "app": c.app,
                "raw_line": c.raw_line,
            })

def read_input_lines(path: Optional[str]) -> List[str]:
    if path:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()
    return sys.stdin.read().splitlines()

def main() -> int:
    ap = argparse.ArgumentParser(description="Generate Markdown/HTML report and CSV export from daed logs.")
    ap.add_argument("logfile", nargs="?", default=None, help="Log file path (default: stdin)")
    ap.add_argument("-o", "--outdir", default=".", help="Output directory (default: current directory)")
    ap.add_argument("--title", default="Daed Network Traffic Analysis Report", help="Report title")
    ap.add_argument("--no-html", action="store_true", help="Do not generate HTML")
    ap.add_argument("--no-md", action="store_true", help="Do not generate Markdown")
    ap.add_argument("--top", type=int, default=15, help="Top N domains to show (default: 15)")
    ap.add_argument("--log-tz", default="UTC", help="Timezone of log 'time=' field (default: UTC)")
    ap.add_argument("--display-tz", default="Asia/Shanghai", help="Timezone used in report output (default: Asia/Shanghai)")
    ap.add_argument("--csv", action="store_true", help="Generate CSV export (connections.csv)")
    ap.add_argument("--csv-only", action="store_true", help="Only generate CSV (implies --csv --no-md --no-html)")
    args = ap.parse_args()

    if args.csv_only:
        args.csv = True
        args.no_md = True
        args.no_html = True

    try:
        log_tz = ZoneInfo(args.log_tz)
    except Exception:
        print(f"ERROR: invalid --log-tz: {args.log_tz}", file=sys.stderr)
        return 2

    try:
        display_tz = ZoneInfo(args.display_tz)
    except Exception:
        print(f"ERROR: invalid --display-tz: {args.display_tz}", file=sys.stderr)
        return 2

    lines = read_input_lines(args.logfile)

    conns: List[ConnRecord] = []
    warnings: List[Dict[str, str]] = []

    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        fields = parse_logfmt_line(line)
        if not fields:
            continue

        typ = classify_log_type(fields)
        if typ == "CONNECTION":
            rec = fields_to_conn(fields, raw_line=raw, log_tz=log_tz)
            if rec:
                conns.append(rec)
        elif typ == "INTERNAL_WARNING":
            warnings.append(fields)

    outdir = os.path.abspath(args.outdir)
    os.makedirs(outdir, exist_ok=True)

    wrote_any = False

    if not args.no_md:
        md_text = render_markdown(
            title=args.title,
            conns=conns,
            warnings=warnings,
            top_n=max(1, args.top),
            log_tz_name=args.log_tz,
            display_tz_name=args.display_tz,
            display_tz=display_tz,
        )
        md_path = os.path.join(outdir, "report.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_text)
        wrote_any = True

        if not args.no_html:
            html_text = render_html(args.title, md_text)
            html_path = os.path.join(outdir, "report.html")
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_text)
            wrote_any = True

    if args.csv:
        csv_path = os.path.join(outdir, "connections.csv")
        write_csv(conns, csv_path, display_tz=display_tz)
        wrote_any = True

    if not wrote_any:
        print("Nothing written. Use default or enable --csv.", file=sys.stderr)
        return 2

    print(f"Parsed connections: {len(conns)}")
    print(f"Parsed internal warnings: {len(warnings)}")
    print(f"Log TZ: {args.log_tz} | Display TZ: {args.display_tz}")
    if not args.no_md:
        print(f"Markdown report: {os.path.join(outdir, 'report.md')}")
    if not args.no_html and not args.no_md:
        print(f"HTML report: {os.path.join(outdir, 'report.html')}")
    if args.csv:
        print(f"CSV export: {os.path.join(outdir, 'connections.csv')}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
