#!/usr/bin/env python3
"""
analyze_clickgrab.py
Parse MHaggis ClickGrab nightly report JSONs and produce _data/clickgrab_trends.yml
for the Detection Chokepoints Jekyll site.

Usage:
    python scripts/analyze_clickgrab.py [path/to/reports/directory]
    python scripts/analyze_clickgrab.py [path/to/clickgrab_combined.json]

Default input: ~/Downloads/MHaggis ClickGrab main nightly_reports/
Output:        _data/clickgrab_trends.yml  (relative to repo root)

Accepts either:
  - A directory: globs all clickgrab_report_*.json files inside it (sorted by name)
  - A single file: processes it as a combined JSON array
"""

import glob
import json
import re
import sys
import os
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_INPUT = os.path.join(
    os.path.expanduser("~"),
    "Downloads",
    "MHaggis ClickGrab main nightly_reports",
)
OUTPUT_PATH = os.path.join(REPO_ROOT, "_data", "clickgrab_trends.yml")

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Cradle families (match against PowerShellCommands string)
# IWR: catches both  iwr ... | iex  and  iex (iwr ...)
RE_IWR = re.compile(r'\biwr\b', re.IGNORECASE)
RE_IRM = re.compile(r'\birm\b', re.IGNORECASE)
RE_WEBCLIENT = re.compile(r'New-Object\s+.*?WebClient', re.IGNORECASE)
RE_CURL = re.compile(r'\bcurl\b', re.IGNORECASE)

# Evasion — mixed-case PowerShell: any capitalisation that isn't fully
# lowercase ("powershell") or title-case ("PowerShell")
RE_PS_ANY = re.compile(r'p(?:o|O)(?:w|W)(?:e|E)(?:r|R)(?:s|S)(?:h|H)(?:e|E)(?:l|L)(?:l|L)', re.IGNORECASE)
RE_PS_NORMAL = re.compile(r'^PowerShell$|^powershell$')

def is_mixed_case_ps(text):
    """Return True if text contains at least one mixed-case PowerShell variant."""
    for m in RE_PS_ANY.finditer(text):
        w = m.group(0)
        if w not in ('PowerShell', 'powershell', 'POWERSHELL'):
            return True
    return False

RE_SELF_DELETE = re.compile(r'\bdel\s+|Remove-Item\b', re.IGNORECASE)
RE_SLEEP = re.compile(r'Start-Sleep\b|-sleep\s', re.IGNORECASE)
RE_HIDDEN = re.compile(r'-w\s+h(?:idden)?\b|-WindowStyle\s+Hidden\b', re.IGNORECASE)

# CDN staging
CDN_PATTERNS = re.compile(r'cdn[-.]|\.wixstatic\.com|irp\.cdn-website\.com', re.IGNORECASE)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def extract_ps_text(record):
    """Return a normalised string of all PowerShell command text in a record."""
    parts = []
    # PowerShellCommands (string or list)
    cmds = record.get('PowerShellCommands')
    if isinstance(cmds, str):
        parts.append(cmds)
    elif isinstance(cmds, list):
        parts.extend(str(c) for c in cmds if c)
    # EncodedPowerShell (newer format)
    enc = record.get('EncodedPowerShell')
    if isinstance(enc, list):
        parts.extend(str(c) for c in enc if c)
    elif isinstance(enc, str) and enc:
        parts.append(enc)
    # HighRiskCommands (newer format)
    hrc = record.get('HighRiskCommands')
    if isinstance(hrc, list):
        parts.extend(str(c) for c in hrc if c)
    elif isinstance(hrc, str) and hrc:
        parts.append(hrc)
    # Decoded Base64 strings
    b64 = record.get('Base64Strings')
    if isinstance(b64, dict):
        decoded = b64.get('Decoded') or b64.get('decoded')
        if decoded:
            parts.append(str(decoded))
    elif isinstance(b64, list):
        for item in b64:
            if isinstance(item, dict):
                decoded = item.get('Decoded') or item.get('decoded')
                if decoded:
                    parts.append(str(decoded))
    return ' '.join(parts)

# Extensions that indicate staging payloads (ps1, hta, vbs, bat, exe, dll, txt used as scripts)
STAGING_EXT = re.compile(r'\.(ps1|hta|vbs|bat|cmd|exe|dll|txt|js|msi|lnk|iso)(\?|$)', re.IGNORECASE)
# Benign domains to skip even if they appear in PowerShellDownloads
BENIGN_SKIP = re.compile(
    r'(google\.com|fontawesome\.com|cloudflare\.com|w3\.org|jquery\.com'
    r'|bootstrapcdn\.com|googleapis\.com|gstatic\.com|github\.com'
    r'|microsoft\.com|windows\.net|amazonaws\.com)$',
    re.IGNORECASE
)

def extract_staging_domains(record):
    """Return list of (domain, is_cdn) tuples from PowerShellDownloads URLs only.
    We deliberately avoid the general 'Urls'/'URLs' page-resource list to prevent
    false positives (Google Analytics, CDN scripts, etc.)."""
    domains = []
    downloads = record.get('PowerShellDownloads') or []
    if isinstance(downloads, dict):
        downloads = [downloads]
    for dl in downloads:
        if not isinstance(dl, dict):
            continue
        url = dl.get('URL') or dl.get('url') or ''
        if url:
            try:
                parsed = urlparse(url)
                host = parsed.hostname or ''
                if host and not BENIGN_SKIP.search(host):
                    is_cdn = bool(CDN_PATTERNS.search(host))
                    domains.append((host, is_cdn))
            except Exception:
                pass
    return domains

def is_malicious(record):
    """Return True if the record contains any malicious indicator."""
    # Check Verdict field if present (newer format)
    verdict = record.get('Verdict') or ''
    if isinstance(verdict, str) and verdict.lower() in ('malicious', 'suspicious', 'high risk'):
        return True
    threat_score = record.get('ThreatScore') or 0
    if threat_score and int(threat_score) > 0:
        return True
    return bool(
        record.get('PowerShellCommands')
        or record.get('ClipboardCommands')
        or record.get('PowerShellDownloads')
        or record.get('HighRiskCommands')
        or record.get('ClipboardManipulation')
    )

def parse_date(ts_str):
    """Parse a timestamp string like '2025-04-17 21:39:51' → 'YYYY-MM-DD'."""
    if not ts_str:
        return None
    try:
        return ts_str[:10]  # slice 'YYYY-MM-DD'
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Report file loading
# ---------------------------------------------------------------------------

def date_from_filename(path):
    """Extract YYYY-MM-DD from report filename for fallback timestamp."""
    name = os.path.basename(path)
    # clickgrab_report_2025-04-17.json
    m = re.search(r'(\d{4}-\d{2}-\d{2})', name)
    if m:
        return m.group(1)
    # clickgrab_report_20260119_030240.json
    m = re.search(r'(\d{4})(\d{2})(\d{2})_', name)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    return None


def load_report_file(path):
    """Load one report JSON file; return list of site records.
    Handles both the original format (list of report objects with 'Sites')
    and the newer format (single dict with lowercase 'sites' + 'report_date').
    """
    fallback_date = date_from_filename(path)
    sites = []
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            data = json.load(f)
    except Exception as e:
        print(f"  WARN: could not parse {os.path.basename(path)}: {e}", file=sys.stderr)
        return sites

    def _ingest(item, report_time=None):
        if not isinstance(item, dict):
            return
        # Normalise timestamp field: prefer Timestamp, then report_time, then filename date
        ts = item.get('Timestamp') or item.get('timestamp') or report_time or fallback_date or ''
        item['Timestamp'] = ts
        sites.append(item)

    if isinstance(data, list):
        # Original format: list of report objects, each with 'Sites'
        for item in data:
            if isinstance(item, dict):
                site_list = item.get('Sites') or item.get('sites') or []
                if site_list:
                    rtime = (
                        item.get('ReportTime') or item.get('report_date')
                        or item.get('timestamp') or fallback_date or ''
                    )
                    for site in site_list:
                        _ingest(site, rtime)
                elif 'Url' in item or 'URL' in item:
                    # Flat list of site records
                    _ingest(item, fallback_date)
    elif isinstance(data, dict):
        # Newer format: single report dict with lowercase 'sites'
        site_list = data.get('Sites') or data.get('sites') or []
        rtime = (
            data.get('ReportTime') or data.get('report_date')
            or data.get('timestamp') or fallback_date or ''
        )
        for site in site_list:
            _ingest(site, rtime)

    return sites


def collect_sites(input_path):
    """Return (sites_list, report_file_paths) from a file or directory."""
    if os.path.isdir(input_path):
        pattern = os.path.join(input_path, 'clickgrab_report_*.json')
        report_files = sorted(glob.glob(pattern))
        # Exclude combined/latest files if accidentally matched
        report_files = [
            p for p in report_files
            if 'combined' not in os.path.basename(p)
            and 'latest' not in os.path.basename(p)
            and 'consolidated' not in os.path.basename(p)
        ]
        print(f"Found {len(report_files)} report files in {input_path}")
        sites = []
        for rfile in report_files:
            sites.extend(load_report_file(rfile))
        return sites, report_files
    else:
        return load_report_file(input_path), [input_path]


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyse(input_path):
    sites, report_files = collect_sites(input_path)
    total_reports = len(report_files)

    if not sites:
        print("ERROR: no site records found.", file=sys.stderr)
        sys.exit(1)

    # --- Per-day accumulators ---
    # Each value: dict with lists/counts
    by_date = defaultdict(lambda: {
        'total': 0,
        'malicious': 0,
        'iwr_iex': 0,
        'irm_iex': 0,
        'webclient': 0,
        'curl': 0,
        'mixed_case': 0,
        'base64': 0,
        'cdn_staging': 0,
        'self_delete': 0,
        'start_sleep': 0,
        'hidden_window': 0,
    })

    domain_counts = defaultdict(int)
    domain_cdn = {}

    cradles_total = defaultdict(int)
    evasion_totals = defaultdict(int)

    for record in sites:
        if not isinstance(record, dict):
            continue

        date = parse_date(record.get('Timestamp') or record.get('ReportTime', ''))
        if not date:
            continue

        day = by_date[date]
        day['total'] += 1

        malicious = is_malicious(record)
        if malicious:
            day['malicious'] += 1

        ps_text = extract_ps_text(record)

        # --- Cradle detection (non-exclusive: count each that applies) ---
        has_iex = bool(re.search(r'\biex\b', ps_text, re.IGNORECASE))
        if RE_IWR.search(ps_text) and has_iex:
            day['iwr_iex'] += 1
            cradles_total['iwr_iex'] += 1
        if RE_IRM.search(ps_text) and has_iex and not RE_IWR.search(ps_text):
            day['irm_iex'] += 1
            cradles_total['irm_iex'] += 1
        if RE_WEBCLIENT.search(ps_text):
            day['webclient'] += 1
            cradles_total['webclient'] += 1
        if RE_CURL.search(ps_text):
            day['curl'] += 1
            cradles_total['curl'] += 1

        # --- Evasion techniques ---
        if ps_text and is_mixed_case_ps(ps_text):
            day['mixed_case'] += 1
            evasion_totals['mixed_case'] += 1

        if record.get('Base64Strings'):
            day['base64'] += 1
            evasion_totals['base64'] += 1

        staging = extract_staging_domains(record)
        has_cdn = any(cdn for _, cdn in staging)
        if has_cdn:
            day['cdn_staging'] += 1
            evasion_totals['cdn_staging'] += 1

        if ps_text and RE_SELF_DELETE.search(ps_text):
            day['self_delete'] += 1
            evasion_totals['self_delete'] += 1

        if ps_text and RE_SLEEP.search(ps_text):
            day['start_sleep'] += 1
            evasion_totals['start_sleep'] += 1

        if ps_text and RE_HIDDEN.search(ps_text):
            day['hidden_window'] += 1
            evasion_totals['hidden_window'] += 1

        # --- Staging domains ---
        for domain, is_cdn in staging:
            domain_counts[domain] += 1
            domain_cdn[domain] = is_cdn

    # Sort dates
    sorted_dates = sorted(by_date.keys())

    # Build top-10 staging domains
    top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    total_sites = sum(d['total'] for d in by_date.values())
    total_malicious = sum(d['malicious'] for d in by_date.values())

    # Infer report count if not found via nested format
    if total_reports == 0:
        # Flat format — estimate from unique timestamps
        total_reports = len(set(
            parse_date(r.get('Timestamp', ''))
            for r in sites if isinstance(r, dict)
        ))

    # --- Build date_range string ---
    date_range = f"{sorted_dates[0]} to {sorted_dates[-1]}" if sorted_dates else "unknown"

    # ---------------------------------------------------------------------------
    # YAML output (hand-built to avoid PyYAML dependency)
    # ---------------------------------------------------------------------------

    lines = []
    lines.append('# Generated by scripts/analyze_clickgrab.py')
    lines.append(f'# Source: {os.path.basename(input_path)}')
    lines.append('')
    lines.append('meta:')
    lines.append(f'  source: {os.path.basename(input_path)}')
    lines.append(f'  date_range: "{date_range}"')
    lines.append(f'  total_reports: {total_reports}')
    lines.append(f'  total_sites_crawled: {total_sites}')
    lines.append(f'  total_malicious: {total_malicious}')
    lines.append(f'  generated: "{datetime.now(timezone.utc).strftime("%Y-%m-%d")}"')
    lines.append('')
    lines.append('daily:')
    for date in sorted_dates:
        d = by_date[date]
        lines.append(f'  - date: "{date}"')
        lines.append(f'    total_sites: {d["total"]}')
        lines.append(f'    malicious: {d["malicious"]}')
        lines.append(f'    cradles:')
        lines.append(f'      iwr_iex: {d["iwr_iex"]}')
        lines.append(f'      irm_iex: {d["irm_iex"]}')
        lines.append(f'      webclient: {d["webclient"]}')
        lines.append(f'      curl: {d["curl"]}')
        lines.append(f'    evasion:')
        lines.append(f'      mixed_case: {d["mixed_case"]}')
        lines.append(f'      base64: {d["base64"]}')
        lines.append(f'      cdn_staging: {d["cdn_staging"]}')
        lines.append(f'      self_delete: {d["self_delete"]}')
        lines.append(f'      start_sleep: {d["start_sleep"]}')
        lines.append(f'      hidden_window: {d["hidden_window"]}')
    lines.append('')
    lines.append('cradles_total:')
    lines.append(f'  iwr_iex: {cradles_total["iwr_iex"]}')
    lines.append(f'  irm_iex: {cradles_total["irm_iex"]}')
    lines.append(f'  webclient: {cradles_total["webclient"]}')
    lines.append(f'  curl: {cradles_total["curl"]}')
    lines.append('')
    lines.append('evasion_totals:')
    lines.append(f'  mixed_case: {evasion_totals["mixed_case"]}')
    lines.append(f'  base64: {evasion_totals["base64"]}')
    lines.append(f'  cdn_staging: {evasion_totals["cdn_staging"]}')
    lines.append(f'  self_delete: {evasion_totals["self_delete"]}')
    lines.append(f'  start_sleep: {evasion_totals["start_sleep"]}')
    lines.append(f'  hidden_window: {evasion_totals["hidden_window"]}')
    lines.append('')
    lines.append('staging_domains:')
    for domain, count in top_domains:
        cdn_flag = 'true' if domain_cdn.get(domain) else 'false'
        lines.append(f'  - domain: "{domain}"')
        lines.append(f'    count: {count}')
        lines.append(f'    cdn: {cdn_flag}')

    # ---------------------------------------------------------------------------
    # Monthly aggregation (for readable trend charts)
    # ---------------------------------------------------------------------------

    from collections import OrderedDict
    monthly = OrderedDict()
    for date in sorted_dates:
        month = date[:7]  # 'YYYY-MM'
        if month not in monthly:
            monthly[month] = {
                'total': 0, 'malicious': 0,
                'iwr_iex': 0, 'irm_iex': 0, 'webclient': 0, 'curl': 0,
                'mixed_case': 0, 'base64': 0, 'cdn_staging': 0,
                'self_delete': 0, 'start_sleep': 0, 'hidden_window': 0,
            }
        d = by_date[date]
        m = monthly[month]
        for key in m:
            m[key] += d.get(key, 0)

    lines.append('')
    lines.append('monthly:')
    for month, m in monthly.items():
        lines.append(f'  - month: "{month}"')
        lines.append(f'    total_sites: {m["total"]}')
        lines.append(f'    malicious: {m["malicious"]}')
        lines.append(f'    cradles:')
        lines.append(f'      iwr_iex: {m["iwr_iex"]}')
        lines.append(f'      irm_iex: {m["irm_iex"]}')
        lines.append(f'      webclient: {m["webclient"]}')
        lines.append(f'      curl: {m["curl"]}')
        lines.append(f'    evasion:')
        lines.append(f'      mixed_case: {m["mixed_case"]}')
        lines.append(f'      base64: {m["base64"]}')
        lines.append(f'      cdn_staging: {m["cdn_staging"]}')
        lines.append(f'      self_delete: {m["self_delete"]}')
        lines.append(f'      start_sleep: {m["start_sleep"]}')
        lines.append(f'      hidden_window: {m["hidden_window"]}')

    return '\n'.join(lines) + '\n'


def main():
    input_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_INPUT

    if not os.path.exists(input_path):
        print(f"ERROR: Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Reading: {input_path}")
    yaml_out = analyse(input_path)

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
        f.write(yaml_out)

    print(f"Written: {OUTPUT_PATH}")


if __name__ == '__main__':
    main()
