#!/usr/bin/env python3
"""
Weekly TTP update script for Detection Chokepoints.

Two phases run every time:

  PHASE 1 — NEW TTP COLLECTION
    Fetches recent threat intel from RSS feeds and the CISA KEV feed, uses Claude
    to extract new attack variants, and patches chokepoint YAML files with new
    Variations and EvolutionTimeline entries. Changes are additive-only and require
    a human PR review before merging.

  PHASE 2 — ACCURACY VALIDATION
    Verifies existing chokepoint data for correctness:
      • MITRE ATT&CK IDs not deprecated or revoked
      • Entries updated within the last 90 days (STALE flag otherwise)
      • Key Intel reference URLs still reachable (404 detection)
      • Claude reviews Variation statuses and descriptions for factual drift

    Accuracy issues are flagged in the PR report but never auto-patched — they
    always require human judgment.

Output:
    /tmp/ttp-update-report.md  — Markdown report used as the GitHub PR body
    scripts/.update-status.json — Machine-readable flags for the Actions workflow
    scripts/.seen_articles.json — Cache of processed article IDs (committed)
    scripts/.mitre_cache.json   — MITRE ATT&CK STIX cache (committed, gitignore ok)

Usage:
    python scripts/update_ttps.py [--dry-run]

Requirements:
    pip install -r requirements-update.txt
    export ANTHROPIC_API_KEY=sk-ant-...
"""

import argparse
import datetime
import glob
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

import anthropic
import feedparser
import requests
import yaml

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent
CHOKEPOINTS_GLOB = str(REPO_ROOT / "chokepoints" / "*" / "*.yml")
SOURCES_PATH = REPO_ROOT / "scripts" / "sources.yml"
SEEN_CACHE_PATH = REPO_ROOT / "scripts" / ".seen_articles.json"
MITRE_CACHE_PATH = REPO_ROOT / "scripts" / ".mitre_cache.json"
STATUS_PATH = REPO_ROOT / "scripts" / ".update-status.json"
REPORT_PATH = Path("/tmp/ttp-update-report.md")

CONFIDENCE_THRESHOLD = 0.7   # Minimum Claude confidence to apply a patch
MAX_ARTICLE_CHARS = 8000     # ~2k tokens per article; enough context, bounded cost
STALE_DAYS = 90              # Flag entries not updated in this many days
LINK_TIMEOUT = 8             # Seconds for HTTP HEAD link checks
MAX_LINKS_PER_CHOKEPOINT = 5 # Cap link checks per entry to avoid hammering sites
MAX_ACCURACY_ARTICLES = 10   # Articles passed to Claude for accuracy review context

MODEL = "claude-opus-4-6"


# ---------------------------------------------------------------------------
# Config + state helpers
# ---------------------------------------------------------------------------

def load_sources() -> dict:
    with open(SOURCES_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_seen_cache() -> set:
    if SEEN_CACHE_PATH.exists():
        with open(SEEN_CACHE_PATH, encoding="utf-8") as f:
            return set(json.load(f))
    return set()


def save_seen_cache(seen: set) -> None:
    SEEN_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(SEEN_CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump(sorted(seen), f, indent=2)


def article_id(url: str, title: str) -> str:
    return hashlib.md5(f"{url}|{title}".encode()).hexdigest()[:16]


def load_chokepoints() -> list:
    """Load all chokepoint YAML files, attaching _source_path to each entry."""
    entries = []
    for path in sorted(glob.glob(CHOKEPOINTS_GLOB)):
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if data and isinstance(data, dict):
            data["_source_path"] = path
            entries.append(data)
    return entries


# ---------------------------------------------------------------------------
# Intel fetching
# ---------------------------------------------------------------------------

def fetch_rss_articles(feeds: list, lookback_days: int, seen: set) -> list:
    """Fetch and filter recent articles from RSS/Atom feeds."""
    articles = []
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=lookback_days)

    for feed_cfg in feeds:
        name = feed_cfg.get("name", feed_cfg.get("url", "unknown"))
        try:
            parsed = feedparser.parse(feed_cfg["url"])
        except Exception as exc:
            print(f"  [WARN] {name}: fetch failed — {exc}", file=sys.stderr)
            continue

        for entry in parsed.entries:
            published = entry.get("published_parsed") or entry.get("updated_parsed")
            if published:
                pub_dt = datetime.datetime(*published[:6], tzinfo=datetime.timezone.utc)
                if pub_dt < cutoff:
                    continue

            url = entry.get("link", "")
            title = entry.get("title", "")
            aid = article_id(url, title)
            if aid in seen:
                continue

            # Merge summary + full content
            parts = [title]
            if entry.get("summary"):
                parts.append(entry.summary)
            for content_block in entry.get("content", []):
                parts.append(content_block.get("value", ""))
            text = "\n\n".join(parts)[:MAX_ARTICLE_CHARS]

            if len(text.strip()) < 100:
                continue

            articles.append({
                "id": aid,
                "url": url,
                "title": title,
                "source": name,
                "published": str(published) if published else "unknown",
                "text": text,
            })

    return articles


def fetch_cisa_kev(url: str, lookback_days: int, seen: set) -> list:
    """Fetch recent entries from the CISA Known Exploited Vulnerabilities feed."""
    if not url:
        return []
    cutoff = datetime.date.today() - datetime.timedelta(days=lookback_days)
    articles = []

    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        print(f"  [WARN] CISA KEV fetch failed — {exc}", file=sys.stderr)
        return []

    for vuln in data.get("vulnerabilities", []):
        date_added = vuln.get("dateAdded", "")
        try:
            if datetime.date.fromisoformat(date_added) < cutoff:
                continue
        except ValueError:
            continue

        cve_id = vuln.get("cveID", "")
        title = f"CISA KEV: {cve_id} — {vuln.get('vulnerabilityName', '')}"
        text = (
            f"CVE: {cve_id}\n"
            f"Vendor/Product: {vuln.get('vendorProject')} {vuln.get('product')}\n"
            f"Vulnerability: {vuln.get('vulnerabilityName')}\n"
            f"Description: {vuln.get('shortDescription')}\n"
            f"Required Action: {vuln.get('requiredAction')}\n"
            f"Known Ransomware Use: {vuln.get('knownRansomwareCampaignUse', 'Unknown')}"
        )
        entry_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        aid = article_id(entry_url, title)
        if aid in seen:
            continue

        articles.append({
            "id": aid,
            "url": entry_url,
            "title": title,
            "source": "CISA KEV",
            "published": date_added,
            "text": text,
        })

    return articles


def fetch_mitre_attack(cache_path: Path) -> tuple:
    """
    Fetch MITRE ATT&CK STIX and return (techniques_dict, is_new).

    techniques_dict maps technique ID (e.g. "T1204.004") to
    {"name": str, "revoked": bool, "deprecated": bool}.
    Falls back to local cache on network failure.
    """
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    techniques = {}

    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        raw = resp.text
    except Exception as exc:
        print(f"  [WARN] MITRE ATT&CK fetch failed — {exc}", file=sys.stderr)
        if cache_path.exists():
            with open(cache_path, encoding="utf-8") as f:
                cached = json.load(f)
            cached.pop("_hash", None)
            return cached, False
        return {}, False

    new_hash = hashlib.md5(raw.encode()).hexdigest()
    old_hash = None
    if cache_path.exists():
        with open(cache_path, encoding="utf-8") as f:
            old_hash = json.load(f).get("_hash")

    try:
        stix = json.loads(raw)
    except json.JSONDecodeError:
        return {}, False

    for obj in stix.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tid = ref.get("external_id", "")
                if tid:
                    techniques[tid] = {
                        "name": obj.get("name", ""),
                        "revoked": bool(obj.get("revoked", False)),
                        "deprecated": bool(obj.get("x_mitre_deprecated", False)),
                    }

    is_new = new_hash != old_hash
    if is_new:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        payload = dict(techniques)
        payload["_hash"] = new_hash
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(payload, f)

    return techniques, is_new


# ---------------------------------------------------------------------------
# Claude helpers
# ---------------------------------------------------------------------------

def build_chokepoint_context(chokepoints: list) -> str:
    """Compact chokepoint summary for Claude's system prompt."""
    sections = []
    for cp in chokepoints:
        variant_names = [
            v.get("Name", "") for v in (cp.get("Variations") or [])
            if isinstance(v, dict)
        ]
        prereqs = "; ".join(str(p) for p in (cp.get("Prerequisites") or []))
        sections.append(
            f"ID: {cp.get('Id')}\n"
            f"Name: {cp.get('Name')}\n"
            f"MITRE: {', '.join(cp.get('MitreIds', []))}\n"
            f"Prerequisites (invariants): {prereqs}\n"
            f"Existing variants (do NOT re-add): {', '.join(variant_names)}"
        )
    return "\n\n---\n\n".join(sections)


def _extract_json_array(text: str) -> list:
    """Pull the first JSON array out of a Claude response string."""
    match = re.search(r"\[.*\]", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass
    text = text.strip()
    if text.startswith("["):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
    return []


def analyze_article_with_claude(
    client: anthropic.Anthropic,
    article: dict,
    chokepoint_context: str,
) -> list:
    """
    Ask Claude to extract new attack variants from a threat intel article.
    Returns a list of finding dicts (may be empty).
    """
    system = f"""You are a threat intelligence analyst maintaining a detection chokepoints knowledge base.

A "chokepoint" is an INVARIANT attack prerequisite that cannot be bypassed regardless of the tool used.
Each chokepoint has Variations (specific tool/method implementations) and an EvolutionTimeline.

EXISTING CHOKEPOINTS:
{chokepoint_context}

YOUR TASK:
Analyze the provided article. Identify any NEW attack variants, techniques, or TTPs described.
For each finding, determine whether it maps to an existing chokepoint above.

Return a JSON array — empty [] if nothing relevant. Each element must have EXACTLY these fields:
{{
  "matched_chokepoint_id": "<UUID from the list above, or null if no match>",
  "variant_name": "<short name, e.g. 'DNS-based ClickFix' or 'EDRKillShifter v3'>",
  "first_seen": "<YYYY-QN, e.g. '2026-Q1'>",
  "notes": "<1-2 sentences for Variations.Notes: delivery, payload, actor if known>",
  "evolution_entry": {{
    "Date": "<YYYY-QN>",
    "Event": "<short event title>",
    "Change": "<what changed vs prior variants>",
    "DetectionImpact": "<effect on existing detection rules>",
    "TheConstant": "<what did NOT change — the invariant>"
  }},
  "confidence": <0.0–1.0>,
  "is_new_chokepoint": <true|false>,
  "reasoning": "<1-2 sentences justifying the mapping>"
}}

RULES:
- Only include genuinely new variants not already in "Existing variants"
- Set confidence < 0.7 for uncertain cases
- Return [] for articles with no relevant new attack behaviors
- Return ONLY valid JSON — no preamble, no explanation outside the array"""

    user = (
        f"SOURCE: {article['source']}\n"
        f"DATE: {article['published']}\n"
        f"TITLE: {article['title']}\n"
        f"URL: {article['url']}\n\n"
        f"{article['text']}"
    )

    try:
        with client.messages.stream(
            model=MODEL,
            max_tokens=2048,
            system=system,
            messages=[{"role": "user", "content": user}],
        ) as stream:
            message = stream.get_final_message()

        response_text = "".join(
            block.text for block in message.content if hasattr(block, "text")
        )
        findings = _extract_json_array(response_text)

        article_ref = {
            "url": article["url"],
            "title": article["title"],
            "source": article["source"],
        }
        for finding in findings:
            finding["_article"] = article_ref

        return findings

    except anthropic.APIError as exc:
        print(f"  [WARN] Claude API error (analysis): {exc}", file=sys.stderr)
        return []


def validate_accuracy_with_claude(
    client: anthropic.Anthropic,
    chokepoint: dict,
    recent_articles: list,
) -> list:
    """
    Ask Claude to review an existing chokepoint for factual inaccuracies based on
    this week's collected articles. Returns a list of issue dicts.
    """
    if not recent_articles:
        return []

    corpus = "\n\n".join(
        f"[{a['source']}] {a['title']}\n{a['text'][:400]}"
        for a in recent_articles[:MAX_ACCURACY_ARTICLES]
    )

    system = """You are a threat intelligence accuracy reviewer for a detection engineering knowledge base.

Your task: review an existing chokepoint entry against recent threat intel and flag factual inaccuracies.

FOCUS ON:
1. Variation Status — should any "Active" variants now be "Disrupted", "Retired", or "Patched"?
2. Descriptions — wrong attribution, incorrect technique names, or outdated factual claims?
3. Prerequisites — are they still accurate and invariant?

DO NOT flag content simply for being old — only flag genuine factual discrepancies that could mislead defenders.
DO NOT suggest adding new content (that is handled separately).

Return a JSON array of issues. Empty [] if none found.
Each issue: {"field": "<field>", "description": "<what is wrong>", "suggestion": "<fix>", "confidence": <0.0-1.0>}
Return ONLY valid JSON."""

    cp_yaml = yaml.dump(
        {
            "Name": chokepoint.get("Name"),
            "MitreIds": chokepoint.get("MitreIds"),
            "Description": chokepoint.get("Description"),
            "Prerequisites": chokepoint.get("Prerequisites"),
            "Variations": chokepoint.get("Variations"),
        },
        default_flow_style=False,
        allow_unicode=True,
    )

    user = (
        f"Review this chokepoint for accuracy:\n\n"
        f"{cp_yaml}\n\n"
        f"RECENT THREAT INTEL (this week):\n{corpus}\n\n"
        f"Are there factual inaccuracies in the chokepoint data above, "
        f"based on the recent intel provided?"
    )

    try:
        with client.messages.stream(
            model=MODEL,
            max_tokens=1024,
            system=system,
            messages=[{"role": "user", "content": user}],
        ) as stream:
            message = stream.get_final_message()

        response_text = "".join(
            block.text for block in message.content if hasattr(block, "text")
        )
        issues = _extract_json_array(response_text)
        # Only surface high-confidence issues to reduce noise
        return [i for i in issues if isinstance(i, dict) and i.get("confidence", 0) >= 0.7]

    except anthropic.APIError as exc:
        print(f"  [WARN] Claude API error (accuracy review): {exc}", file=sys.stderr)
        return []


# ---------------------------------------------------------------------------
# Structural accuracy checks (no Claude required)
# ---------------------------------------------------------------------------

def check_mitre_ids(chokepoints: list, mitre_techniques: dict) -> list:
    """Flag MITRE ATT&CK technique IDs that are revoked, deprecated, or missing."""
    issues = []
    for cp in chokepoints:
        for mid in cp.get("MitreIds") or []:
            tech = mitre_techniques.get(mid)
            base = {
                "chokepoint_id": cp.get("Id"),
                "chokepoint_name": cp.get("Name"),
                "severity": "DEPRECATED_MITRE_ID",
                "field": "MitreIds",
            }
            if tech is None:
                issues.append({**base,
                    "description": f"{mid} not found in current MITRE ATT&CK STIX",
                    "suggestion": f"Verify {mid} still exists or find its replacement technique",
                })
            elif tech.get("revoked"):
                issues.append({**base,
                    "description": f"{mid} ({tech['name']}) is REVOKED in MITRE ATT&CK",
                    "suggestion": f"Find the replacement technique for {mid}",
                })
            elif tech.get("deprecated"):
                issues.append({**base,
                    "description": f"{mid} ({tech['name']}) is DEPRECATED in MITRE ATT&CK",
                    "suggestion": f"Consider updating {mid} to the current recommended technique",
                })
    return issues


def check_stale_entries(chokepoints: list) -> list:
    """Flag chokepoints not updated in STALE_DAYS days."""
    issues = []
    today = datetime.date.today()
    cutoff = today - datetime.timedelta(days=STALE_DAYS)

    for cp in chokepoints:
        last_updated = cp.get("LastUpdated", "")
        base = {
            "chokepoint_id": cp.get("Id"),
            "chokepoint_name": cp.get("Name"),
            "severity": "STALE",
            "field": "LastUpdated",
        }
        if not last_updated:
            issues.append({**base,
                "description": "No LastUpdated date set",
                "suggestion": "Add a LastUpdated date",
            })
            continue
        try:
            updated = datetime.date.fromisoformat(str(last_updated))
            if updated < cutoff:
                days_old = (today - updated).days
                issues.append({**base,
                    "description": (
                        f"Last updated {days_old} days ago ({last_updated}). "
                        f"Review for new variants or timeline entries."
                    ),
                    "suggestion": "Review and update LastUpdated if the content is still current",
                })
        except ValueError:
            pass

    return issues


def check_reference_links(chokepoints: list) -> list:
    """HTTP HEAD check on Intel reference URLs to detect 404s."""
    issues = []
    session = requests.Session()
    session.headers["User-Agent"] = (
        "Mozilla/5.0 (compatible; DetectionChokepoints-LinkChecker/1.0)"
    )

    for cp in chokepoints:
        checked = 0
        for intel_entry in (cp.get("Intel") or []):
            if checked >= MAX_LINKS_PER_CHOKEPOINT:
                break
            for ref in (intel_entry.get("References") or []):
                url = ref if isinstance(ref, str) else ref.get("Url", "")
                if not url or not url.startswith("http"):
                    continue
                try:
                    resp = session.head(url, timeout=LINK_TIMEOUT, allow_redirects=True)
                    if resp.status_code == 404:
                        issues.append({
                            "chokepoint_id": cp.get("Id"),
                            "chokepoint_name": cp.get("Name"),
                            "severity": "BROKEN_LINK",
                            "field": "Intel.References",
                            "description": f"404 Not Found: {url}",
                            "suggestion": (
                                "Find an archived version (web.archive.org) or remove this reference"
                            ),
                        })
                    checked += 1
                    time.sleep(0.5)  # polite crawl delay
                except requests.RequestException:
                    pass  # Network errors are inconclusive — skip silently

    return issues


# ---------------------------------------------------------------------------
# YAML patching
# ---------------------------------------------------------------------------

def _variant_exists(chokepoint: dict, variant_name: str) -> bool:
    """Case-insensitive substring check for duplicate variant names."""
    name_lower = variant_name.lower()
    for v in (chokepoint.get("Variations") or []):
        if isinstance(v, dict):
            existing = v.get("Name", "").lower()
            if name_lower in existing or existing in name_lower:
                return True
    return False


def apply_yaml_patch(chokepoint: dict, finding: dict, dry_run: bool = False) -> bool:
    """
    Append a new Variation and EvolutionTimeline entry to a chokepoint YAML file.
    Returns True if the file was changed (or would be in dry-run mode).
    """
    path = chokepoint["_source_path"]
    slug = Path(path).name

    new_variation = {
        "Name": finding["variant_name"],
        "FirstSeen": finding["first_seen"],
        "Status": "Active",
        "Notes": finding["notes"],
    }

    ev = finding.get("evolution_entry") or {}
    new_timeline = {
        "Date": ev.get("Date", finding["first_seen"]),
        "Event": ev.get("Event", finding["variant_name"]),
        "Change": ev.get("Change", ""),
        "DetectionImpact": ev.get("DetectionImpact", "No change to detection logic"),
        "TheConstant": ev.get("TheConstant", ""),
    }

    if dry_run:
        print(f"    [DRY-RUN] Would add '{finding['variant_name']}' → {slug}")
        return True

    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data.get("Variations"), list):
        data["Variations"] = []
    data["Variations"].append(new_variation)

    if not isinstance(data.get("EvolutionTimeline"), list):
        data["EvolutionTimeline"] = []
    data["EvolutionTimeline"].append(new_timeline)

    data["LastUpdated"] = datetime.date.today().isoformat()

    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    return True


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(
    applied: list,
    skipped: list,
    accuracy_issues: list,
    articles_processed: int,
    dry_run: bool,
) -> str:
    today = datetime.date.today().isoformat()
    mode = " *(dry-run — no files changed)*" if dry_run else ""

    lines = [
        f"# Weekly TTP Update — {today}{mode}",
        "",
        f"**Articles analyzed:** {articles_processed}  ",
        f"**New variants applied:** {len(applied)}  ",
        f"**Candidates skipped (low confidence / duplicate / new chokepoint):** {len(skipped)}  ",
        f"**Accuracy issues flagged:** {len(accuracy_issues)}",
        "",
    ]

    # New TTPs applied
    if applied:
        lines += ["## New TTPs Applied", ""]
        for f in applied:
            art = f.get("_article", {})
            lines += [
                f"### {f['variant_name']}",
                f"- **Mapped to:** {f.get('matched_chokepoint_id', 'unknown')}",
                f"- **First seen:** {f['first_seen']}",
                f"- **Confidence:** {f['confidence']:.0%}",
                f"- **Notes:** {f['notes']}",
                f"- **Source:** [{art.get('title', art.get('url', 'Link'))}]({art.get('url', '')})",
                f"- **Reasoning:** {f.get('reasoning', '')}",
                "",
            ]
    else:
        lines += ["## New TTPs Applied", "", "No new variants found this week.", ""]

    # Skipped candidates
    if skipped:
        lines += ["## Skipped Candidates", ""]
        lines += ["| Variant | Confidence | Reason |", "|---|---|---|"]
        for f in skipped:
            skip_reason = f.get("_skip_reason", "unknown")
            reason_label = {
                "duplicate": "Already documented",
                "low_confidence": f"Low confidence ({f.get('confidence', 0):.0%})",
                "new_chokepoint": "Potential new chokepoint — manual review needed",
                "no_match": "No matching chokepoint found",
            }.get(skip_reason, skip_reason)
            lines.append(f"| {f.get('variant_name', '?')} | {f.get('confidence', 0):.0%} | {reason_label} |")
        lines.append("")

    # Accuracy issues
    if accuracy_issues:
        lines += [
            "## Accuracy Issues — Review Required",
            "",
            "> These issues require human judgment. **No automatic changes were made.**",
            "> Review each item and update the relevant chokepoint YAML manually.",
            "",
        ]

        severity_order = [
            "DEPRECATED_MITRE_ID",
            "BROKEN_LINK",
            "POTENTIAL_INACCURACY",
            "STALE",
        ]
        labels = {
            "DEPRECATED_MITRE_ID": "MITRE ATT&CK ID Issues",
            "BROKEN_LINK": "Broken Reference Links",
            "POTENTIAL_INACCURACY": "Potential Inaccuracies (Claude Review)",
            "STALE": "Stale Entries (90+ days)",
        }

        by_sev: dict = {s: [] for s in severity_order}
        for issue in accuracy_issues:
            sev = issue.get("severity", "POTENTIAL_INACCURACY")
            by_sev.setdefault(sev, []).append(issue)

        for sev in severity_order:
            group = by_sev.get(sev, [])
            if not group:
                continue
            lines += [f"### {labels.get(sev, sev)}", ""]
            for issue in group:
                lines += [
                    f"**{issue.get('chokepoint_name', 'Unknown')}** — `{issue.get('field', '')}`",
                    f"> {issue.get('description', '')}",
                    f"*Suggested fix: {issue.get('suggestion', 'Manual review required')}*",
                    "",
                ]
    else:
        lines += [
            "## Accuracy Validation",
            "",
            "All checks passed — no accuracy issues found.",
            "",
        ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(dry_run: bool = False) -> None:
    print(f"Detection Chokepoints — Weekly TTP Update {'(DRY RUN) ' if dry_run else ''}")
    print("=" * 60)

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY environment variable not set.", file=sys.stderr)
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)

    sources = load_sources()
    lookback_days = sources.get("lookback_days", 7)
    max_articles = sources.get("max_articles", 30)

    seen = load_seen_cache()
    chokepoints = load_chokepoints()
    print(f"Loaded {len(chokepoints)} chokepoints")

    chokepoint_map = {cp["Id"]: cp for cp in chokepoints}
    chokepoint_context = build_chokepoint_context(chokepoints)

    # ------------------------------------------------------------------
    # Phase 1 — Fetch intel
    # ------------------------------------------------------------------
    print(f"\n[1/4] Fetching intel (lookback: {lookback_days} days)...")

    articles: list = []
    articles += fetch_rss_articles(sources.get("rss_feeds", []), lookback_days, seen)
    articles += fetch_cisa_kev(sources.get("cisa_kev_url", ""), lookback_days, seen)
    articles = articles[:max_articles]

    print(f"  {len(articles)} new articles to analyze")

    # ------------------------------------------------------------------
    # Phase 2 — Claude TTP extraction
    # ------------------------------------------------------------------
    print(f"\n[2/4] Analyzing articles with Claude ({MODEL})...")

    all_findings: list = []
    for i, article in enumerate(articles, 1):
        print(f"  [{i}/{len(articles)}] {article['source']}: {article['title'][:65]}...")
        findings = analyze_article_with_claude(client, article, chokepoint_context)
        all_findings.extend(findings)

    applied: list = []
    skipped: list = []

    for finding in all_findings:
        confidence = finding.get("confidence", 0)

        if confidence < CONFIDENCE_THRESHOLD:
            finding["_skip_reason"] = "low_confidence"
            skipped.append(finding)
            continue

        if finding.get("is_new_chokepoint"):
            finding["_skip_reason"] = "new_chokepoint"
            skipped.append(finding)
            continue

        matched_id = finding.get("matched_chokepoint_id")
        cp = chokepoint_map.get(matched_id)
        if not cp:
            finding["_skip_reason"] = "no_match"
            skipped.append(finding)
            continue

        if _variant_exists(cp, finding["variant_name"]):
            finding["_skip_reason"] = "duplicate"
            skipped.append(finding)
            continue

        if apply_yaml_patch(cp, finding, dry_run=dry_run):
            applied.append(finding)
            # Reload the patched file so the next iteration sees the new variant
            if not dry_run:
                with open(cp["_source_path"], encoding="utf-8") as f:
                    refreshed = yaml.safe_load(f)
                refreshed["_source_path"] = cp["_source_path"]
                chokepoint_map[matched_id] = refreshed
                chokepoints = list(chokepoint_map.values())
                chokepoint_context = build_chokepoint_context(chokepoints)

    new_seen = seen | {a["id"] for a in articles}
    if not dry_run:
        save_seen_cache(new_seen)

    print(f"  Applied: {len(applied)}, Skipped: {len(skipped)}")

    # ------------------------------------------------------------------
    # Phase 3 — Accuracy validation
    # ------------------------------------------------------------------
    print("\n[3/4] Validating existing data accuracy...")
    accuracy_issues: list = []

    # 3a: MITRE ID check
    print("  Fetching MITRE ATT&CK STIX for technique ID validation...")
    mitre_techniques, _ = fetch_mitre_attack(MITRE_CACHE_PATH)
    if mitre_techniques:
        mitre_issues = check_mitre_ids(chokepoints, mitre_techniques)
        print(f"  MITRE ID issues: {len(mitre_issues)}")
        accuracy_issues.extend(mitre_issues)

    # 3b: Stale entry check
    stale_issues = check_stale_entries(chokepoints)
    print(f"  Stale entries (>{STALE_DAYS} days): {len(stale_issues)}")
    accuracy_issues.extend(stale_issues)

    # 3c: Reference link health check
    print("  Checking Intel reference links...")
    link_issues = check_reference_links(chokepoints)
    print(f"  Broken links: {len(link_issues)}")
    accuracy_issues.extend(link_issues)

    # 3d: Claude factual accuracy review (per chokepoint, using this week's articles as context)
    print("  Running Claude accuracy review per chokepoint...")
    for cp in chokepoints:
        issues = validate_accuracy_with_claude(client, cp, articles)
        for issue in issues:
            issue["chokepoint_id"] = cp.get("Id")
            issue["chokepoint_name"] = cp.get("Name")
            issue["severity"] = "POTENTIAL_INACCURACY"
        accuracy_issues.extend(issues)
        if issues:
            print(f"    {cp.get('Name')}: {len(issues)} potential issue(s)")

    print(f"  Total accuracy issues: {len(accuracy_issues)}")

    # ------------------------------------------------------------------
    # Phase 4 — Report + status flags
    # ------------------------------------------------------------------
    print("\n[4/4] Writing report...")
    report = generate_report(applied, skipped, accuracy_issues, len(articles), dry_run)
    REPORT_PATH.write_text(report, encoding="utf-8")
    print(f"  Report → {REPORT_PATH}")

    # Write machine-readable status for the Actions workflow
    non_stale_issues = [i for i in accuracy_issues if i.get("severity") != "STALE"]
    status = {
        "has_changes": len(applied) > 0,
        "has_issues": len(non_stale_issues) > 0,
        "applied_count": len(applied),
        "skipped_count": len(skipped),
        "accuracy_issues_count": len(accuracy_issues),
        "non_stale_issues_count": len(non_stale_issues),
        "articles_processed": len(articles),
        "date": datetime.date.today().isoformat(),
    }
    if not dry_run:
        STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(STATUS_PATH, "w", encoding="utf-8") as f:
            json.dump(status, f, indent=2)

    if dry_run:
        print("\n--- REPORT PREVIEW (first 3000 chars) ---")
        print(report[:3000])
    else:
        summary = []
        if applied:
            summary.append(f"{len(applied)} new variant(s) applied")
        if non_stale_issues:
            summary.append(f"{len(non_stale_issues)} accuracy issue(s) flagged")
        if not summary:
            summary.append("no changes, no critical issues")
        print(f"\nDone: {', '.join(summary)}.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Weekly TTP update + accuracy validation for Detection Chokepoints"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without writing any chokepoint files",
    )
    args = parser.parse_args()
    main(dry_run=args.dry_run)
