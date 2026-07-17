#!/usr/bin/env python3
"""extract_edge_infra.py -- recompute the edge-exploits page's hand-curated infra
sections (scanner-UA fingerprints, staging hosts, multi-device operators) from the
raw Defused export(s) in ~/Downloads.

The trend YAML (transform_defused_csv.py) only carries aggregates: daily totals,
per-CVE, per-target, exploit/recon. The scanner/staging/operator tables on the page
are UA- and payload-level, which those aggregates don't hold -- so before this they
were hand-curated from a one-off Mar-Apr pass and went stale on every refresh.

This is the missing build step. It applies the SAME newest-wins day-dedup as
transform_defused_csv.py (a newer export's day replaces an older one) so its numbers
reconcile with the page's charts, then emits:
  * scanner UAs: named-tool vs browser-masquerade split + self-identifying %
  * staging URLs: host/path, hits, distinct source IPs, first/last seen
  * operators:   attacker IP -> distinct decoy types + hits + first/last seen

OPSEC (decision #009, hard): reads private capture; writes NOTHING to the repo.
Prints a DEFANGED, curated view to stdout for manual promotion into the page. No IP
or payload is persisted. ASN for the chosen hosts is filled separately via
enrich_staging_domains.py --hosts (IPinfo/rdap) or Team Cymru, same as clickgrab.

Usage:
    py scripts/extract_edge_infra.py                 # all export_shared_*.csv in ~/Downloads
    py scripts/extract_edge_infra.py --top 20
    py scripts/extract_edge_infra.py --asn           # resolve staging/operator IP ASNs via Cymru (keyless)
"""
from __future__ import annotations

import argparse
import csv
import glob
import os
import re
import socket
import sys
from collections import Counter, defaultdict
from pathlib import Path

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
DEFAULT_GLOB = os.path.expanduser("~/Downloads/export_shared_*.csv")

UA_RE = re.compile(r"User-Agent:\s*([^\r\n]+)", re.I)
URL_RE = re.compile(r"https?://([A-Za-z0-9.\-]+(?::\d+)?(?:/[^\s'\"|;)>]*)?)", re.I)

# Named automation tools -- self-identifying, even when Mozilla-prefixed (Blaster).
# Order-independent substring match, case-insensitive.
TOOL_TOKENS = [
    "python-requests", "go-http-client", "libredtail-http", "curl", "wget",
    "l9scan", "leakix", "ffuf", "sqlmap", "nuclei", "nmap", "masscan", "zgrab",
    "httpx", "python-httpx", "aiohttp", "okhttp", "java/", "libwww", "winhttp",
    "node-fetch", "axios", "nikto", "gobuster", "feroxbuster", "dirbuster",
    "blaster", "hello, world", "custom-async", "zmap", "censys", "shodan",
]
# Hosts that are never payload staging (metadata svc, XML schemas, loopback, the
# decoy's own callbacks). Curated out so the staging ranking is signal.
NOISE_HOST_RE = re.compile(
    r"^(127\.0\.0\.1|localhost|169\.254\.169\.254|.*\.w3\.org|.*xmlsoap\.org|"
    r"schemas\..*|.*\.oasis-open\.org|.*\.example\.(com|org))",
    re.I,
)


def defang(s: str) -> str:
    s = re.sub(r"\.(?=\d)", "[.]", s)                      # IPv4 dots
    s = re.sub(r"\.(?=[A-Za-z]{2,}(?:[:/]|$))", "[.]", s)  # TLD dot
    return s.replace("http://", "hxxp://").replace("https://", "hxxps://")


def classify_ua(ua: str) -> str:
    low = ua.lower()
    for t in TOOL_TOKENS:
        if t in low:
            return "tool"
    if low.startswith("mozilla/") or "applewebkit" in low or "gecko/" in low:
        return "browser"
    return "other"


def tool_name(ua: str) -> str:
    """Collapse a tool UA to its family label (version-agnostic) for charting."""
    low = ua.lower()
    for t in TOOL_TOKENS:
        if t in low:
            return {
                "go-http-client": "Go-http-client", "python-requests": "python-requests",
                "libredtail-http": "libredtail-http", "l9scan": "l9scan (LeakIX)",
                "leakix": "l9scan (LeakIX)", "java/": "Java", "hello, world": "Hello, world",
            }.get(t, t)
    return ua[:40]


def aggregate_file(path):
    """One export CSV -> {iso_date: aggregate}. Row-level extraction; day-level
    newest-wins merge happens in build()."""
    days = {}
    with open(path, encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            dt = (r.get("Datetime") or "")
            iso = dt[:10]
            if not iso:
                continue
            d = days.setdefault(iso, {
                "ua": Counter(), "ua_class": Counter(),
                "url_hits": Counter(), "url_ips": defaultdict(set),
                "url_seen": {},                       # host/path -> [first_dt, last_dt]
                "op_hits": Counter(), "op_decoy": defaultdict(set),
                "op_seen": {}, "op_prod": defaultdict(Counter),
            })
            raw = r.get("Raw Request") or ""
            ip = (r.get("Attacker IP") or "").strip()
            decoy = (r.get("Decoy Type") or "").strip()

            m = UA_RE.search(raw)
            if m:
                ua = m.group(1).strip()
                d["ua"][ua] += 1
                d["ua_class"][classify_ua(ua)] += 1
            else:
                d["ua_class"]["none"] += 1

            for um in URL_RE.finditer(raw):
                host = um.group(1)
                if NOISE_HOST_RE.match(host):
                    continue
                d["url_hits"][host] += 1
                if ip:
                    d["url_ips"][host].add(ip)
                fs = d["url_seen"].get(host)
                if fs is None:
                    d["url_seen"][host] = [dt, dt]
                else:
                    if dt < fs[0]:
                        fs[0] = dt
                    if dt > fs[1]:
                        fs[1] = dt

            if ip:
                d["op_hits"][ip] += 1
                if decoy:
                    d["op_decoy"][ip].add(decoy)
                    d["op_prod"][ip][decoy] += 1
                os_ = d["op_seen"].get(ip)
                if os_ is None:
                    d["op_seen"][ip] = [dt, dt]
                else:
                    if dt < os_[0]:
                        os_[0] = dt
                    if dt > os_[1]:
                        os_[1] = dt
    return days


def build(paths):
    live = {}
    seen = set()
    for p in sorted(paths):
        fdays = aggregate_file(p)
        ov = seen & set(fdays)
        if ov:
            print(f"  # {Path(p).name}: {len(ov)} overlapping day(s) replaced (newest wins)",
                  file=sys.stderr)
        live.update(fdays)          # newest export's day replaces older -- matches transform
        seen |= set(fdays)

    ua = Counter()
    ua_class = Counter()
    url_hits = Counter()
    url_ips = defaultdict(set)
    url_seen = {}
    op_hits = Counter()
    op_decoy = defaultdict(set)
    op_seen = {}
    op_prod = defaultdict(Counter)
    for d in live.values():
        ua.update(d["ua"])
        ua_class.update(d["ua_class"])
        url_hits.update(d["url_hits"])
        for h, ips in d["url_ips"].items():
            url_ips[h] |= ips
        for h, (fs, ls) in d["url_seen"].items():
            cur = url_seen.get(h)
            if cur is None:
                url_seen[h] = [fs, ls]
            else:
                cur[0] = min(cur[0], fs)
                cur[1] = max(cur[1], ls)
        op_hits.update(d["op_hits"])
        for ip, ds in d["op_decoy"].items():
            op_decoy[ip] |= ds
        for ip, (fs, ls) in d["op_seen"].items():
            cur = op_seen.get(ip)
            if cur is None:
                op_seen[ip] = [fs, ls]
            else:
                cur[0] = min(cur[0], fs)
                cur[1] = max(cur[1], ls)
        for ip, c in d["op_prod"].items():
            op_prod[ip].update(c)
    return dict(days=sorted(live), ua=ua, ua_class=ua_class, url_hits=url_hits,
                url_ips=url_ips, url_seen=url_seen, op_hits=op_hits,
                op_decoy=op_decoy, op_seen=op_seen, op_prod=op_prod)


def cymru_bulk(ips):
    out = {}
    ips = {i for i in ips if re.match(r"^\d+\.\d+\.\d+\.\d+$", i)}
    if not ips:
        return out
    q = "begin\nverbose\n" + "\n".join(sorted(ips)) + "\nend\n"
    with socket.create_connection(("whois.cymru.com", 43), timeout=60) as s:
        s.sendall(q.encode())
        buf = b""
        while True:
            chunk = s.recv(8192)
            if not chunk:
                break
            buf += chunk
    for line in buf.decode("utf-8", "replace").splitlines():
        if line.startswith("Bulk mode") or "AS Name" in line:
            continue
        parts = [x.strip() for x in line.split("|")]
        if len(parts) < 7:
            continue
        asn, ip, prefix, cc, registry, allocated, asname = parts[:7]
        out[ip] = f"AS{asn} {asname}" + (f" [{cc}]" if cc else "")
    return out


def host_ip(hostport: str) -> str:
    h = hostport.split("/")[0].split(":")[0]
    return h if re.match(r"^\d+\.\d+\.\d+\.\d+$", h) else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--glob", default=DEFAULT_GLOB)
    ap.add_argument("--top", type=int, default=18)
    ap.add_argument("--asn", action="store_true", help="resolve IP ASNs via Team Cymru (keyless)")
    args = ap.parse_args()

    paths = [Path(p) for p in sorted(glob.glob(args.glob))]
    if not paths:
        raise SystemExit(f"No export CSV found ({args.glob})")
    print(f"# inputs: {[p.name for p in paths]}", file=sys.stderr)
    b = build(paths)

    days = b["days"]
    print(f"\n=== WINDOW: {days[0]} .. {days[-1]}  ({len(days)} distinct days, newest-wins) ===")

    total_ua = sum(b["ua_class"].values())
    tool = b["ua_class"]["tool"]
    browser = b["ua_class"]["browser"]
    none = b["ua_class"]["none"]
    other = b["ua_class"]["other"]
    print("\n=== SCANNER / UA CLASS (self-identifying vs masquerade) ===")
    print(f"  total rows           : {total_ua}")
    print(f"  named tool           : {tool:>7}  ({100*tool/total_ua:.1f}%)")
    print(f"  browser-masquerade   : {browser:>7}  ({100*browser/total_ua:.1f}%)")
    print(f"  other UA             : {other:>7}  ({100*other/total_ua:.1f}%)")
    print(f"  no UA line           : {none:>7}  ({100*none/total_ua:.1f}%)")

    tool_fam = Counter()
    for ua, c in b["ua"].items():
        if classify_ua(ua) == "tool":
            tool_fam[tool_name(ua)] += c
    print("\n=== TOP TOOL FAMILIES (chart candidates) ===")
    tf_total = sum(tool_fam.values())
    for name, c in tool_fam.most_common(12):
        print(f"  {c:>7}  {100*c/tf_total:5.1f}%  {name}")

    print("\n=== TOP STAGING URLs (defanged; hits / distinct src IPs / first..last) ===")
    staging_ips = set()
    for host, c in b["url_hits"].most_common(args.top * 2):
        fs, ls = b["url_seen"][host]
        nips = len(b["url_ips"][host])
        # focus on payload-delivery shapes: .sh/.ts/install/deploy/miner or bare-IP roots
        looks_stage = bool(re.search(r"\.(sh|ts|elf|bin|py)$|/install/|deploy|miner|/sh$|muie|check\.sh", host, re.I)) or (host_ip(host) and host.count("/") <= 1)
        if not looks_stage:
            continue
        ip = host_ip(host)
        if ip:
            staging_ips.add(ip)
        print(f"  {c:>6} | {nips:>4} IPs | {fs[:10]}..{ls[:10]} | {defang(host)}")

    print("\n=== TOP MULTI-DEVICE OPERATORS (defanged; #decoys / hits / first..last) ===")
    ops = sorted(b["op_hits"].keys(),
                 key=lambda ip: (len(b["op_decoy"][ip]), b["op_hits"][ip]), reverse=True)
    op_ips = ops[:args.top]
    for ip in op_ips:
        ndecoy = len(b["op_decoy"][ip])
        hits = b["op_hits"][ip]
        fs, ls = b["op_seen"][ip]
        prods = ", ".join(p for p, _ in b["op_prod"][ip].most_common(6))
        print(f"  {ndecoy:>2} decoys | {hits:>5} hits | {fs[:10]}..{ls[:10]} | {defang(ip):>18} | {prods}")

    if args.asn:
        print("\n=== ASN (Team Cymru, keyless) for staging + operator IPs ===", file=sys.stderr)
        allips = staging_ips | set(op_ips)
        asn = cymru_bulk(allips)
        for ip in sorted(allips):
            print(f"  {defang(ip):>18}  {asn.get(ip, 'unresolved')}")


if __name__ == "__main__":
    main()
