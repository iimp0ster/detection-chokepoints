#!/usr/bin/env python3
"""Transform Defused honeypot export CSV(s) into _data/edge_exploits.yml.

Why this exists: the edge-exploits trends page used to be hand-typed. This reads
the Defused export(s) (default: legacy export_shared_*.csv, current
defused-intel-*.csv files, and numbered export(N).csv UI downloads),
aggregates per day, and writes combined = frozen baseline + live so history
ACCUMULATES instead of being overwritten (decision #002). Aggregates only -- no
IP address ever reaches the repo (decision #001); only counts.

Data shape facts this relies on (verified against the May 2026 export and the
page it reproduces):
  * The published longitudinal series is restricted to Defused severity "major",
    matching the page's original high/critical scope. Newer all-products exports
    also contain "medium" rows; those are summarized separately as the latest raw
    export snapshot and never mixed into the comparable historical series.
  * Each export covers a time WINDOW, not a cumulative dump. Windows are merged
    at DAY granularity, keeping the FULLEST capture of each day (max row count
    across the exports covering it). Exports are snapshots of an append-only feed,
    so two exports of the same COMPLETE day agree; they differ only when one caught
    the day partially -- a window-start cutoff, a window-end (export-time) cutoff, or
    a row-cap truncation. The higher count is the more complete one, so max-wins.
    NOT row-deduped: identical rows in the same second are distinct rapid-fire
    events the page counts (the newer "Defused Alert ID" column, when present, is
    not used -- windows are disjoint or resolved by max, so dedup isn't needed).

The first export (Mar 14-Apr 13) was taken from a mobile session and not
retained; it survives only as scripts/edge_exploits_baseline.yml (frozen, never
recomputed). baseline = (page combined) - (CSV live), validated once.

Usage:
    py scripts/transform_defused_csv.py                 # all matching CSVs in ~/Downloads
    py scripts/transform_defused_csv.py --input X.csv   # one or more specific exports
    py scripts/transform_defused_csv.py --check-seed    # assert it reproduces the page
"""
from __future__ import annotations

import argparse
import csv
import glob
import os
import re
from collections import Counter
from datetime import date, timedelta
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
BASELINE_FILE = REPO / "scripts" / "edge_exploits_baseline.yml"
OUT = REPO / "_data" / "edge_exploits.yml"
DEFAULT_GLOBS = [
    os.path.expanduser("~/Downloads/export_shared_*.csv"),
    os.path.expanduser("~/Downloads/defused-intel-*.csv"),
    os.path.expanduser("~/Downloads/export(*).csv"),
]
PUBLISHED_SEVERITIES = {"major"}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
MONTHS = {1: "Jan", 2: "Feb", 3: "Mar", 4: "Apr", 5: "May", 6: "Jun",
          7: "Jul", 8: "Aug", 9: "Sep", 10: "Oct", 11: "Nov", 12: "Dec"}

# CSV "Decoy Type" -> page display name. Only entries that differ from the raw
# string need listing; everything else passes through. Mapping lives here (logic
# the page contract depends on), not in the data file.
DECOY_DISPLAY = {
    "cPanel": "cPanel WHM",
    "Cisco Catalyst SD-WAN (vManage)": "Cisco SD-WAN",
    "Wordpress // W3 Total Cache": "WordPress W3 Total Cache",
}

# Page headline stat cells, keyed by CVE. baseline contributes the first-window
# count (frozen); live adds the rest.
HEADLINE = [
    ("citrixbleed2", "CitrixBleed 2",     "CVE-2025-5777"),
    ("nextjs_rce",   "Next.js RCE (new)", "CVE-2025-55182"),
    ("cpanel_whm",   "cPanel WHM chain",  "CVE-2026-41940"),
]

# The 6-day hole between the two export windows; rendered as a visible gap.
GAP_DAYS = ["2026-04-14", "2026-04-15", "2026-04-16", "2026-04-17", "2026-04-18"]

# Defused's console export caps at 50,000 rows: the 2026-07-03 AND 2026-07-10 exports
# both hit exactly 50,000, each with the truncation landing on its oldest day (the window
# START, since a fuller day sits at the newest end). unverified: no documented limit, but
# two independent exports at exactly 50,000 make a configured cap near-certain. When a file
# hits this, its oldest day is an undercount of unknown true size; unless another export
# captured that day more completely (winning the per-day max), it is rendered as a GAP --
# an honest hole a later narrow export can fill -- not a truncated floor drawn as a bar.
EXPORT_ROW_CAP = 50000


class _QuoteCommaDumper(yaml.SafeDumper):
    """SafeDumper that single-quotes strings containing a comma, so display
    values like "25,420" survive the YAML round-trip into Jekyll -- which
    otherwise reads an unquoted 25,420 and drops the comma."""


def _repr_str(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data,
                                   style="'" if "," in data else None)


_QuoteCommaDumper.add_representer(str, _repr_str)


def label_for(iso: str) -> str:
    y, m, d = (int(x) for x in iso.split("-"))
    return f"{MONTHS[m]} {d}"


def _consecutive_ranges(isos):
    """Sorted iso date strings -> list of (start, end) for each consecutive run.
    Used to collapse a list of missing days into human-readable gap ranges."""
    if not isos:
        return []
    isos = sorted(isos)
    ranges = [[isos[0], isos[0]]]
    for iso in isos[1:]:
        prev_end = date.fromisoformat(ranges[-1][1])
        if date.fromisoformat(iso) == prev_end + timedelta(days=1):
            ranges[-1][1] = iso
        else:
            ranges.append([iso, iso])
    return [(r[0], r[1]) for r in ranges]


def human(n: int) -> str:
    return f"{n / 1000:.1f}k" if n >= 1000 else str(n)


def classify(alert: str) -> str:
    """Stage from the Alert verb. "Vulnerability Exploited (...)" is the only
    weaponized verb Defused emits; everything else (Associated with / scan /
    vuln check / exposure / unauthenticated access) is pre-exploitation probing
    of a specific CVE. Splits weaponization from recon without changing the
    high/critical export scope."""
    return "exploit" if "vulnerability exploited" in alert.lower() else "recon"


def _source_ip(value: str) -> str:
    """Normalize an exported source address for in-memory cardinality only."""
    value = value.strip()
    if value.count(":") == 1 and "." in value:
        return value.rsplit(":", 1)[0]
    return value


def aggregate_file(path):
    """One export CSV -> (published daily records, file metadata).

    File metadata is aggregate-only and lets build() detect row caps and select the
    newest export for the raw-scope snapshot. The published daily records include
    only PUBLISHED_SEVERITIES so unlike-for-like historical charts stay comparable.
    """
    days = {}
    n = 0
    raw_dates = Counter()
    severities = Counter()
    with open(path, encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            n += 1
            iso = (r.get("Datetime") or "")[:10]
            if not iso:
                continue
            raw_dates[iso] += 1
            severity = (r.get("Severity") or "").strip().lower()
            severities[severity or "(blank)"] += 1
            if severity not in PUBLISHED_SEVERITIES:
                continue
            rec = days.setdefault(iso, {"total": 0, "ips": set(),
                                        "cve": Counter(), "decoy": Counter(),
                                        "cls": Counter(), "cve_cls": Counter()})
            rec["total"] += 1
            ip = _source_ip(r.get("Attacker IP") or "")
            # Newer exports append the source :port (137.0.0.1:52396); older ones give
            # the bare IP. Strip an IPv4 port so a source counts once, not once per
            # ephemeral port, and stays consistent across the two export formats.
            if ip:
                rec["ips"].add(ip)
            decoy = (r.get("Decoy Type") or "").strip()
            rec["decoy"][DECOY_DISPLAY.get(decoy, decoy)] += 1
            alert = r.get("Alert") or ""
            cls = classify(alert)
            rec["cls"][cls] += 1
            m = CVE_RE.search(alert)
            if m:
                rec["cve"][m.group(0)] += 1
                rec["cve_cls"][(m.group(0), cls)] += 1
    return days, {
        "row_count": n,
        "raw_dates": raw_dates,
        "severities": severities,
        "raw_min": min(raw_dates) if raw_dates else None,
        "raw_max": max(raw_dates) if raw_dates else None,
    }


def latest_export_snapshot(path, file_meta):
    """Aggregate the newest raw export without mixing its scope into the trend.

    The oldest day of a capped export is omitted because its count is truncated.
    The newest day is retained but labeled partial, matching the chart convention.
    Only counts and source cardinalities leave this function; no address is written.
    """
    capped = file_meta["row_count"] >= EXPORT_ROW_CAP
    truncated_date = file_meta["raw_min"] if capped else None
    severity = Counter()
    decoys = Counter()
    alerts = Counter()
    cves = Counter()
    cls = Counter()
    ips = set()
    major_decoys = Counter()
    major_cves = Counter()
    major_cls = Counter()
    major_ips = set()
    dates = Counter()

    with open(path, encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            iso = (r.get("Datetime") or "")[:10]
            if not iso or iso == truncated_date:
                continue
            sev = (r.get("Severity") or "").strip().lower() or "(blank)"
            alert = (r.get("Alert") or "").strip()
            decoy_raw = (r.get("Decoy Type") or "").strip()
            decoy = DECOY_DISPLAY.get(decoy_raw, decoy_raw)
            stage = classify(alert)
            ip = _source_ip(r.get("Attacker IP") or "")
            hit = CVE_RE.search(alert)

            dates[iso] += 1
            severity[sev] += 1
            decoys[decoy] += 1
            alerts[alert] += 1
            cls[stage] += 1
            if ip:
                ips.add(ip)
            if hit:
                cves[hit.group(0)] += 1

            if sev in PUBLISHED_SEVERITIES:
                major_decoys[decoy] += 1
                major_cls[stage] += 1
                if ip:
                    major_ips.add(ip)
                if hit:
                    major_cves[hit.group(0)] += 1

    usable_events = sum(dates.values())
    major_events = sum(major_cls.values())
    usable_min = min(dates) if dates else None
    usable_max = max(dates) if dates else None

    def ranked(counter, key, limit=8):
        return [{key: name, "count": count, "display": f"{count:,}",
                 "pct": round(100 * count / max(1, usable_events), 1)}
                for name, count in counter.most_common(limit)]

    return {
        "source_file": path.name,
        "observed_window": (f"{label_for(file_meta['raw_min'])} - "
                            f"{label_for(file_meta['raw_max'])}, {file_meta['raw_max'][:4]}"),
        "usable_window": (f"{label_for(usable_min)} - {label_for(usable_max)}, {usable_max[:4]}"
                          if usable_min else "none"),
        "row_count": file_meta["row_count"],
        "row_count_display": f"{file_meta['row_count']:,}",
        "row_cap": capped,
        "truncated_date": truncated_date,
        "partial_date": file_meta["raw_max"],
        "usable_events": usable_events,
        "usable_events_display": f"{usable_events:,}",
        "unique_ips": len(ips),
        "severity": [{"name": name, "count": count,
                      "pct": round(100 * count / max(1, usable_events), 1)}
                     for name, count in severity.most_common()],
        "exploit": cls["exploit"],
        "recon": cls["recon"],
        "exploit_pct": round(100 * cls["exploit"] / max(1, usable_events), 1),
        "recon_pct": round(100 * cls["recon"] / max(1, usable_events), 1),
        "top_targets": ranked(decoys, "name"),
        "top_alerts": ranked(alerts, "name"),
        "top_cves": ranked(cves, "id"),
        "major_events": major_events,
        "major_events_display": f"{major_events:,}",
        "major_pct": round(100 * major_events / max(1, usable_events), 1),
        "non_major_events": usable_events - major_events,
        "non_major_pct": round(100 * (usable_events - major_events)
                               / max(1, usable_events), 1),
        "major_unique_ips": len(major_ips),
        "major_exploit": major_cls["exploit"],
        "major_recon": major_cls["recon"],
        "major_targets": [{"name": name, "count": count, "display": f"{count:,}"}
                          for name, count in major_decoys.most_common(8)],
        "major_cves": [{"id": name, "count": count, "display": f"{count:,}"}
                       for name, count in major_cves.most_common(8)],
    }


def build(paths):
    baseline = yaml.safe_load(BASELINE_FILE.read_text(encoding="utf-8"))
    # Merge exports at day granularity. Max-wins makes path order irrelevant and
    # keeps the fullest capture where export windows overlap. Disjoint windows union.
    live_days = {}
    seen_days = set()
    # (path, oldest_date, that_file's_count_for_oldest_date) for every capped export --
    # resolved to a final gap-day set AFTER the merge, since another export covering the
    # same day more completely would win the max and leave it a normal (non-gap) day.
    capped_candidates = []
    file_metas = {}
    for p in sorted(paths):
        fdays, file_meta = aggregate_file(p)
        file_metas[p] = file_meta
        excluded = file_meta["row_count"] - sum(d["total"] for d in fdays.values())
        if excluded:
            print(f"  {p.name}: excluded {excluded:,} non-major row(s) from the "
                  "published high/critical series.")
        overlap = seen_days & set(fdays)
        if overlap:
            print(f"  {p.name}: {len(overlap)} day(s) overlap an earlier export; "
                  "kept the fuller (higher-count) capture per day.")
        if file_meta["row_count"] >= EXPORT_ROW_CAP and file_meta["raw_min"]:
            oldest = file_meta["raw_min"]
            capped_candidates.append((p, oldest, fdays.get(oldest, {}).get("total", 0)))
        # Per-day MAX-wins: keep the fullest capture of each day (see module docstring).
        for iso, rec in fdays.items():
            if iso not in live_days or rec["total"] > live_days[iso]["total"]:
                live_days[iso] = rec
        seen_days |= set(fdays)
    if not live_days:
        raise SystemExit("No dated rows parsed from the export(s).")

    # A row-capped export undercounts its oldest day (the cap truncates the window
    # start). If no other export captured that day more completely, its true total is
    # unknown -- render it as a GAP rather than publish a truncated floor as if it were
    # the count. A later narrow export covering just that day supplies a complete count
    # (wins the max) and closes the gap automatically, no code change needed.
    capped_gap_days = set()
    for p, oldest, day_total in capped_candidates:
        if oldest not in live_days or live_days[oldest]["total"] <= day_total:
            capped_gap_days.add(oldest)
            print(f"  WARN {p.name}: hit the {EXPORT_ROW_CAP}-row cap -- oldest day "
                  f"{oldest} is truncated with no fuller capture; rendered as a GAP.")
    for iso in capped_gap_days:
        live_days.pop(iso, None)

    live_total = sum(d["total"] for d in live_days.values())
    live_cve, live_decoy, live_ips = Counter(), Counter(), set()
    for d in live_days.values():
        live_cve.update(d["cve"])
        live_decoy.update(d["decoy"])
        live_ips |= d["ips"]

    # --- exploit-vs-recon split + per-CVE recon->exploit lead time ----------
    # Live window only: the baseline window kept no per-alert verbs to classify.
    cls_total = Counter()
    cve_first = {}            # cve -> {cls: earliest iso date}
    cve_exploit = Counter()   # cve -> weaponized hit count
    for iso in sorted(live_days):
        rec = live_days[iso]
        cls_total.update(rec["cls"])
        for (cve, cls), n in rec["cve_cls"].items():
            if n:
                cve_first.setdefault(cve, {}).setdefault(cls, iso)  # ascending = earliest
                if cls == "exploit":
                    cve_exploit[cve] += n
    lead_times = []
    for cve, firsts in cve_first.items():
        if "recon" in firsts and "exploit" in firsts:
            lead = (date.fromisoformat(firsts["exploit"])
                    - date.fromisoformat(firsts["recon"])).days
            if lead >= 1:  # recon genuinely preceded weaponization (>=1 day)
                lead_times.append({"cve": cve, "recon_first": firsts["recon"],
                                   "exploit_first": firsts["exploit"],
                                   "lead_days": lead, "exploit_count": cve_exploit[cve]})
    lead_times.sort(key=lambda x: (-x["lead_days"], -x["exploit_count"]))
    lead_times = lead_times[:12]

    targets = Counter()
    for name, n in baseline["targets"].items():
        targets[name] += n
    for name, n in live_decoy.items():
        targets[name] += n

    headline = []
    for key, label, cve in HEADLINE:
        count = baseline["headline_cves"].get(cve, 0) + live_cve.get(cve, 0)
        headline.append({"key": key, "label": label, "cve": cve,
                         "count": count, "display": f"{count:,}"})

    artifact_day = max(live_days)
    live_min, live_max = min(live_days), max(live_days)

    # Any day between the earliest and latest live-window date with no export
    # covering it is a genuine gap -- distinct from GAP_DAYS (the one-time, frozen
    # baseline-to-live seam). Detected fresh every run so a new gap (e.g. exports
    # not taken for weeks) shows up automatically instead of needing a code edit.
    full_range = []
    d = date.fromisoformat(live_min)
    end = date.fromisoformat(live_max)
    while d <= end:
        full_range.append(d.isoformat())
        d += timedelta(days=1)
    # Days in [live_min, live_max] with no usable count render as a gap: either no
    # export covered them (a true gap) or their only coverage was a row-capped
    # truncation dropped above (capped_gap_days). Both are rendered identically; only
    # the date_range_note distinguishes the reason.
    gap_days = [iso for iso in full_range if iso not in live_days]
    uncovered_days = [iso for iso in gap_days if iso not in capped_gap_days]
    if gap_days:
        print(f"  WARN: {len(gap_days)} day(s) in the live window render as a gap "
              f"({gap_days[0]} to {gap_days[-1]}).")

    # Keep every calendar day in the recon/exploit series. Without explicit null
    # rows, Chart.js renders an uncovered interval as if the preceding and following
    # days were adjacent (for example, Jul 16 directly beside Aug 24).
    exploit_recon_daily = []
    for iso in full_range:
        if iso not in live_days:
            exploit_recon_daily.append({"date": iso, "label": "",
                                        "exploit": None, "recon": None})
            continue
        rec = live_days[iso]
        exploit_recon_daily.append({"date": iso, "label": label_for(iso),
                                    "exploit": rec["cls"].get("exploit", 0),
                                    "recon": rec["cls"].get("recon", 0)})

    daily = []
    for row in baseline["daily"]:
        daily.append({"date": row["date"], "label": label_for(row["date"]),
                      "total": row["total"]})
    for iso in GAP_DAYS:
        daily.append({"date": iso, "label": "", "total": None})
    for iso in full_range:
        if iso not in live_days:
            daily.append({"date": iso, "label": "", "total": None})
            continue
        d = live_days[iso]
        flags = "*" if iso == artifact_day else ""
        entry = {"date": iso, "label": label_for(iso) + flags,
                 "total": d["total"], "unique_ips": len(d["ips"])}
        if iso == artifact_day:
            entry["artifact"] = True
        daily.append(entry)

    total_events = baseline["total_events"] + live_total
    base_min = baseline["daily"][0]["date"]

    def _gap_note(isos, reason):
        out = []
        for gap_start, gap_end in _consecutive_ranges(sorted(isos)):
            span = label_for(gap_start) + (f"-{label_for(gap_end)}" if gap_end != gap_start else "")
            out.append(f"gap {span} ({reason})")
        return out

    notes = ["two export windows, 6-day gap Apr 14-18"]
    notes += _gap_note(uncovered_days, "no export covers this period")
    notes += _gap_note(capped_gap_days, "export row-capped; complete count unavailable")
    date_range_note = "; ".join(notes)

    # CitrixBleed 2 (CVE-2025-5777) needs the same calendar semantics as the
    # all-traffic chart. The frozen baseline records only non-zero Citrix days, but
    # its daily window lets us fill the remaining dates as zero. Live-window gaps stay
    # null, not zero: they represent absent/truncated telemetry, not measured silence.
    month_numbers = {name: number for number, name in MONTHS.items()}
    baseline_cb2 = {}
    for label, count in zip(baseline["cb2_daily"]["labels"],
                            baseline["cb2_daily"]["data"]):
        month, day = label.split()
        baseline_cb2[f"2026-{month_numbers[month]:02d}-{int(day):02d}"] = count

    cb2_dates, cb2_labels, cb2_data = [], [], []
    for row in baseline["daily"]:
        iso = row["date"]
        cb2_dates.append(iso)
        cb2_labels.append(label_for(iso))
        cb2_data.append(baseline_cb2.get(iso, 0))
    for iso in GAP_DAYS:
        cb2_dates.append(iso)
        cb2_labels.append("")
        cb2_data.append(None)
    for iso in full_range:
        cb2_dates.append(iso)
        if iso not in live_days:
            cb2_labels.append("")
            cb2_data.append(None)
            continue
        cb2_labels.append(label_for(iso))
        cb2_data.append(live_days[iso]["cve"].get("CVE-2025-5777", 0))
    cb2_daily = {"dates": cb2_dates, "labels": cb2_labels, "data": cb2_data}

    latest_path = max(
        file_metas,
        key=lambda p: (file_metas[p]["raw_max"] or "", p.stat().st_mtime),
    )
    latest_snapshot = latest_export_snapshot(latest_path, file_metas[latest_path])

    out = {
        "meta": {
            "source": "Defused Cyber honeypot telemetry",
            "source_url": "https://defusedcyber.com/",
            "severity_scope": "Defused 'major' alerts (high/critical page scope)",
            "baseline_window": baseline["window"],
            "live_window": f"{label_for(live_min)} - {label_for(live_max)}, {live_max[:4]}",
            "date_range": f"{label_for(base_min)} - {label_for(live_max)}, {live_max[:4]}",
            "date_range_note": date_range_note,
            "total_events": total_events,
            "total_display": human(total_events),
            "total_events_display": f"{total_events:,}",
            "decoy_count_display": baseline["decoy_count_display"],
            "cve_count_display": baseline["cve_count_display"],
            "live_decoy_count": len(live_decoy),
            "live_cve_count": len(live_cve),
            "live_unique_ips": len(live_ips),
            "generated": date.today().isoformat(),
        },
        "headline": headline,
        "targets": [{"name": n, "count": c, "display": f"{c:,}"}
                    for n, c in sorted(targets.items(), key=lambda kv: (-kv[1], kv[0]))],
        "daily": daily,
        "cb2_daily": cb2_daily,
        "cves": [{"id": c, "count": n}
                 for c, n in sorted(live_cve.items(), key=lambda kv: (-kv[1], kv[0]))],
        "exploit_recon": {
            "exploit_total": cls_total["exploit"],
            "recon_total": cls_total["recon"],
            "exploit_pct": round(100 * cls_total["exploit"]
                                 / max(1, cls_total["exploit"] + cls_total["recon"])),
            "daily": exploit_recon_daily,
        },
        "lead_times": lead_times,
        "latest_export": latest_snapshot,
    }
    return out, live_total, live_cve, live_ips


def check_seed(out, live_total, live_cve, live_ips) -> None:
    """Assert the seed reproduces the page exactly. Seed-time only -- the refresher
    runs without this, since new exports legitimately change these numbers."""
    checks = [
        ("live_total", live_total, 10419),
        ("combined_total", out["meta"]["total_events"], 25420),
        ("live CVE-2025-5777", live_cve.get("CVE-2025-5777"), 3033),
        ("live CVE-2025-55182", live_cve.get("CVE-2025-55182"), 2683),
        ("live CVE-2026-41940", live_cve.get("CVE-2026-41940"), 1515),
        ("live_unique_ips", len(live_ips), 1034),
        ("exploit_total", out["exploit_recon"]["exploit_total"], 7005),
        ("recon_total", out["exploit_recon"]["recon_total"], 3414),
    ]
    tg = {t["name"]: t["count"] for t in out["targets"]}
    for name, want in [("Citrix NetScaler", 11995), ("React Server", 2683),
                       ("FortiWeb", 2037), ("cPanel WHM", 1515),
                       ("Cisco SD-WAN", 1383), ("SAP Netweaver", 1341),
                       ("Ivanti Connect Secure", 1035), ("SonicWall SMA", 834)]:
        checks.append(("target " + name, tg.get(name), want))
    hd = {h["key"]: h["count"] for h in out["headline"]}
    checks += [("headline citrixbleed2", hd["citrixbleed2"], 11145),
               ("headline nextjs_rce", hd["nextjs_rce"], 2683),
               ("headline cpanel_whm", hd["cpanel_whm"], 1515)]

    failed = 0
    for name, got, want in checks:
        ok = got == want
        failed += not ok
        print(("  ok   " if ok else "  FAIL ") + f"{name}: got {got} want {want}")
    if failed:
        raise SystemExit(f"SEED VALIDATION FAILED: {failed} check(s)")
    print("  seed reproduces the page: all %d checks pass" % len(checks))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", action="append",
                    help="specific export CSV; repeat for multiple files")
    ap.add_argument("--glob", action="append",
                    help="export glob; repeat for multiple patterns")
    ap.add_argument("--check-seed", action="store_true",
                    help="assert output reproduces the page (seed-time validation)")
    args = ap.parse_args()

    if args.input:
        paths = [Path(p) for p in args.input]
        looked_for = args.input
    else:
        patterns = args.glob or DEFAULT_GLOBS
        looked_for = patterns
        paths = [Path(p) for pattern in patterns for p in glob.glob(pattern)]
    paths = sorted({p.resolve() for p in paths})
    if not paths:
        raise SystemExit(f"No export CSV found (looked for {looked_for})")

    out, live_total, live_cve, live_ips = build(paths)
    if args.check_seed:
        check_seed(out, live_total, live_cve, live_ips)

    header = (
        "# Generated by scripts/transform_defused_csv.py -- do not hand-edit.\n"
        "# Combined = frozen baseline (scripts/edge_exploits_baseline.yml, Mar 14-Apr 13)\n"
        "# + live window recomputed from Defused export CSV(s). Aggregates only; no IPs.\n\n"
    )
    OUT.write_text(
        header + yaml.dump(out, Dumper=_QuoteCommaDumper, sort_keys=False,
                           allow_unicode=True, width=200, default_flow_style=False),
        encoding="utf-8", newline="\n")
    print("OK wrote", OUT.relative_to(REPO),
          f"({len(paths)} CSV, total {out['meta']['total_events']}, "
          f"live {live_total}, unique_ips {len(live_ips)}, "
          f"decoys {out['meta']['live_decoy_count']}, cves {out['meta']['live_cve_count']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
