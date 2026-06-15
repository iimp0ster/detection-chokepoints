#!/usr/bin/env python3
"""Local ASN / hosting-provenance enrichment for the edge-exploits trend (PR-2).

Reads attacker IPs from the Defused export(s) in ~/Downloads, resolves each to an
ASN via Team Cymru's keyless bulk whois (authoritative), optionally cross-checks a
sample against IPinfo, labels them with the curated bulletproof map, and writes
per-month hosting-provenance AGGREGATES to the gitignored cache. Cumulative-unique
IPs are tracked in a HyperLogLog sketch so the count survives without ever storing
an IP (decision #009).

OPSEC (hard rule -- IOCs out of persistence entirely): runs locally; reads private
capture + an optional key from the environment. NO IP address and NO key is ever
written to any file -- not the repo, not even the local cache. Only ASN numbers,
AS-org names, and counts are persisted. ASN/org are public routing data; the page
(PR-3) publishes from these aggregates.

Cymru is the workhorse (one keyless connection resolves every IP); IPinfo is a
light optional cross-check on the busiest ASNs -- disagreement is a rotation/BP
tell. Set IPINFO_TOKEN in the env or .env to enable it.

Usage:
    py scripts/enrich_asns.py                 # all export_shared_*.csv in ~/Downloads
    py scripts/enrich_asns.py --no-ipinfo     # Cymru only
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import socket
import sys
import urllib.request
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hll import HyperLogLog  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
BP_MAP_FILE = REPO / "scripts" / "bulletproof_asns.yml"
CACHE = REPO / "cache"
ASN_OUT = CACHE / "edge_exploits_asn.json"
HLL_OUT = CACHE / "edge_exploits_hll.json"
DEFAULT_GLOB = os.path.expanduser("~/Downloads/export_shared_*.csv")


def get_token() -> str | None:
    t = os.environ.get("IPINFO_TOKEN")
    if t:
        return t.strip()
    envf = REPO / ".env"
    if envf.exists():
        for line in envf.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("IPINFO_TOKEN="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


def read_events(paths):
    """Return (events, unique_ips): events is Counter[(month, ip)], unique_ips a set.
    IPs are held in memory only -- never returned to a caller that persists them."""
    events = Counter()
    unique = set()
    for p in paths:
        with open(p, encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                ip = (r.get("Attacker IP") or "").strip()
                month = (r.get("Datetime") or "")[:7]
                if ip and month:
                    events[(month, ip)] += 1
                    unique.add(ip)
    return events, unique


def cymru_bulk(ips: set[str]) -> dict:
    """Resolve IPs -> ASN via Team Cymru's bulk whois (whois.cymru.com:43, keyless).
    One connection handles the whole set. Returns {ip: {asn, org, prefix, cc, allocated}}."""
    out: dict = {}
    if not ips:
        return out
    query = "begin\nverbose\n" + "\n".join(sorted(ips)) + "\nend\n"
    with socket.create_connection(("whois.cymru.com", 43), timeout=60) as s:
        s.sendall(query.encode())
        buf = b""
        while True:
            chunk = s.recv(8192)
            if not chunk:
                break
            buf += chunk
    for line in buf.decode("utf-8", "replace").splitlines():
        if line.startswith("Bulk mode") or line.startswith("AS ") or "AS Name" in line:
            continue
        parts = [x.strip() for x in line.split("|")]
        if len(parts) < 7:
            continue
        asn, ip, prefix, cc, registry, allocated, asname = parts[:7]
        out[ip] = {
            "asn": int(asn) if asn.isdigit() else None,
            "org": asname or None,
            "prefix": prefix or None,
            "cc": cc or None,
            "allocated": allocated or None,
        }
    return out


def ipinfo_asn(ip: str, token: str) -> int | None:
    """Best-effort ASN from IPinfo (cross-check only). Returns None on any failure."""
    try:
        url = f"https://ipinfo.io/{ip}/json?token={token}"
        req = urllib.request.Request(url, headers={"User-Agent": "detection-chokepoints/1.0"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read())
        org = data.get("org") or (data.get("asn") or {}).get("asn") or ""
        # both "AS13335 Cloudflare" and {"asn":"AS13335"} forms start with AS<digits>
        for tok in str(org).replace("AS", " AS").split():
            if tok.startswith("AS") and tok[2:].isdigit():
                return int(tok[2:])
    except Exception:
        pass
    return None


def load_bp_map() -> dict:
    data = yaml.safe_load(BP_MAP_FILE.read_text(encoding="utf-8")) or {}
    return {int(k): v for k, v in (data.get("asns") or {}).items()}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", help="one export CSV (default: all export_shared_*.csv in ~/Downloads)")
    ap.add_argument("--glob", default=DEFAULT_GLOB)
    ap.add_argument("--no-ipinfo", action="store_true", help="skip the IPinfo cross-check")
    args = ap.parse_args()

    paths = [Path(args.input)] if args.input else [Path(p) for p in sorted(glob.glob(args.glob))]
    if not paths:
        raise SystemExit(f"No export CSV found (looked for {args.glob})")
    CACHE.mkdir(exist_ok=True)

    events, unique = read_events(paths)
    if not unique:
        raise SystemExit("No attacker IPs parsed from the export(s).")
    print(f"{len(unique)} unique IPs across {len(paths)} export(s); resolving ASNs via Team Cymru...")

    cymru = cymru_bulk(unique)
    bp = load_bp_map()

    def label(asn, org):
        if asn in bp:
            return bp[asn].get("name") or org, bool(bp[asn].get("bulletproof"))
        return org, False

    # per-(month, asn) and all-window event tallies -- counts only, never IPs
    month_asn = defaultdict(Counter)         # month -> Counter[asn]
    asn_meta = {}                            # asn -> {org, name, bulletproof}
    asn_total = Counter()
    bp_events = 0
    total_events = 0
    for (month, ip), n in events.items():
        rec = cymru.get(ip) or {}
        asn = rec.get("asn")
        org = rec.get("org") or "Unresolved"
        name, is_bp = label(asn, org)
        key = asn if asn is not None else f"org:{org}"
        month_asn[month][key] += n
        asn_total[key] += n
        asn_meta[key] = {"asn": asn, "org": org, "name": name, "bulletproof": is_bp}
        total_events += n
        if is_bp:
            bp_events += n

    # cumulative-unique sketch (load existing, add this run's IPs, persist)
    sketch = HyperLogLog.load(HLL_OUT)
    for ip in unique:
        sketch.add(ip)
    sketch.save(HLL_OUT)
    cumulative_unique = sketch.count()

    # optional IPinfo cross-check on a representative IP from each top ASN
    agree = disagree = 0
    token = None if args.no_ipinfo else get_token()
    if token:
        top_asns = [k for k, _ in asn_total.most_common(8) if isinstance(k, int)]
        rep_ip = {}
        for (month, ip), _n in events.items():
            a = (cymru.get(ip) or {}).get("asn")
            if a in top_asns and a not in rep_ip:
                rep_ip[a] = ip
        for a, ip in rep_ip.items():
            other = ipinfo_asn(ip, token)
            if other is None:
                continue
            agree, disagree = (agree + 1, disagree) if other == a else (agree, disagree + 1)
        print(f"IPinfo cross-check: {agree} agree / {disagree} disagree on ASN "
              f"(disagreement = a rotation/prefix-boundary tell)")
    else:
        print("IPinfo cross-check skipped (no IPINFO_TOKEN; Cymru is authoritative).")

    def rows(counter):
        out = []
        for key, n in counter.most_common():
            m = asn_meta[key]
            out.append({"asn": m["asn"], "org": m["org"], "name": m["name"],
                        "bulletproof": m["bulletproof"], "events": n})
        return out

    result = {
        "generated": date.today().isoformat(),
        "source": "Defused honeypot attacker IPs, enriched via Team Cymru (+ IPinfo cross-check)",
        "cumulative_unique_ips": cumulative_unique,
        "total_events": total_events,
        "bulletproof_events": bp_events,
        "bulletproof_pct": round(100 * bp_events / total_events) if total_events else 0,
        "asn_totals": rows(asn_total),
        "months": {month: rows(c) for month, c in sorted(month_asn.items())},
        "ipinfo_crosscheck": {"agree": agree, "disagree": disagree, "enabled": bool(token)},
    }
    ASN_OUT.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(f"\nOK wrote {ASN_OUT.relative_to(REPO)} (aggregates only, no IPs)")
    print(f"  cumulative unique IPs (HLL): {cumulative_unique}")
    print(f"  bulletproof-labeled traffic: {result['bulletproof_pct']}% of events")
    print("  top ASNs by events:")
    for r in result["asn_totals"][:8]:
        flag = " [BP]" if r["bulletproof"] else ""
        asn = f"AS{r['asn']}" if r["asn"] else "(unresolved)"
        print(f"    {r['events']:>5}  {asn:<10} {r['name']}{flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
