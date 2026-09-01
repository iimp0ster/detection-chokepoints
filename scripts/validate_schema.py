#!/usr/bin/env python3
"""Validate chokepoint YAML entries against schema/chokepoint-schema.yml, plus the
generated trends data files (_data/*.yml) against the structure their page
templates depend on.

Run locally or in CI: `python scripts/validate_schema.py`
To validate one review draft without checking unrelated generated data:
`python scripts/validate_schema.py drafts/<tactic>/<slug>/<entry>.yml`
Exits non-zero if any entry has errors, so it can gate a pull request.

Why a standalone validator rather than a JSON-Schema file: the chokepoint
schema mixes simple enums with cross-file invariants (Sigma paths must exist on
disk, the parent directory must match a declared tactic). Those checks are
clearer in code than in a declarative schema, and the error messages can point
at the exact file and field a contributor needs to fix.
"""
from __future__ import annotations

import re
import sys
from datetime import date, timedelta
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
CHOKEPOINTS_DIR = REPO / "chokepoints"

# ── enum constraints (mirror schema/chokepoint-schema.yml) ───────────────────
PRIORITY = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
PREVALENCE = {"VERY HIGH", "HIGH", "MEDIUM", "LOW", "EMERGING"}
DIFFICULTY = {"LOW", "MEDIUM", "HIGH"}
TACTICS = {
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
}
TIER = {"Research", "Hunt", "Analyst"}
# Variations.Status and Detections.ExpectedFPRate are authored as a leading
# severity/status token optionally followed by detail (a date, a range, or a
# parenthetical caveat). We validate the LEADING token against a controlled
# vocabulary and let the trailing context through, so genuine typos still fail
# but the house style ("Medium (password managers...)", "Disrupted (Oct 2024)")
# passes.
VARIATION_STATUS = {"Active", "Declining", "Emerging", "Legacy",
                    "Disrupted", "Defunct", "Inactive", "Dismantled"}
INTEL_TIER = {"primary", "supporting"}
FP_RATE_RE = re.compile(r"^\s*(very\s+)?(low|medium|high)(\s*[-/]\s*(low|medium|high))?\b", re.I)

REQUIRED = [
    "Name", "Id", "MitreIds", "Tactics", "Techniques", "DetectionPriority",
    "ThreatPrevalence", "DetectionDifficulty", "Description", "LastUpdated", "Author",
]
LIST_FIELDS = ["MitreIds", "Tactics", "Techniques"]

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# directory name -> the tactic the entry is expected to declare
DIR_TO_TACTIC = {
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


def check_enum(errors, label, value, allowed):
    if value is not None and value not in allowed:
        errors.append(f"{label}: {value!r} is not one of {sorted(allowed)}")


def leading_token(value: str) -> str:
    """First word of an authored status string, e.g. 'Disrupted (Oct 2024)' -> 'Disrupted'."""
    return re.split(r"[\s(/-]", value.strip(), maxsplit=1)[0] if isinstance(value, str) else value


def validate_entry(path: Path) -> list[str]:
    errors: list[str] = []
    rel = path.relative_to(REPO).as_posix()
    rel_parts = Path(rel).parts
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"{rel}: YAML parse error: {exc}"]
    if not isinstance(data, dict):
        return [f"{rel}: top-level YAML is not a mapping"]

    # required fields present + non-empty
    for field in REQUIRED:
        if field not in data or data[field] in (None, "", [], {}):
            errors.append(f"{rel}: missing required field {field!r}")

    # list-typed fields really are lists
    for field in LIST_FIELDS:
        if field in data and not isinstance(data[field], list):
            errors.append(f"{rel}: {field} must be a list")

    # scalar enums
    check_enum(errors, f"{rel}: DetectionPriority", data.get("DetectionPriority"), PRIORITY)
    check_enum(errors, f"{rel}: ThreatPrevalence", data.get("ThreatPrevalence"), PREVALENCE)
    check_enum(errors, f"{rel}: DetectionDifficulty", data.get("DetectionDifficulty"), DIFFICULTY)

    # tactics
    for t in data.get("Tactics", []) or []:
        check_enum(errors, f"{rel}: Tactics entry", t, TACTICS)

    # id / date / mitre formats
    if isinstance(data.get("Id"), str) and not UUID_RE.match(data["Id"]):
        errors.append(f"{rel}: Id {data['Id']!r} is not a UUIDv4")
    if isinstance(data.get("LastUpdated"), str) and not DATE_RE.match(str(data["LastUpdated"])):
        errors.append(f"{rel}: LastUpdated {data['LastUpdated']!r} is not ISO YYYY-MM-DD")
    for mid in data.get("MitreIds", []) or []:
        if not (isinstance(mid, str) and MITRE_RE.match(mid)):
            errors.append(f"{rel}: MitreIds entry {mid!r} is not a Txxxx[.xxx] id")

    # nested enums + Sigma path existence
    for st in data.get("Chokepoints", []) or []:
        if isinstance(st, dict):
            check_enum(errors, f"{rel}: Chokepoints.DetectionTier", st.get("DetectionTier"), TIER)
            ref = st.get("SigmaRef")
            if ref and not (REPO / ref).exists():
                errors.append(f"{rel}: Chokepoints.SigmaRef path does not exist: {ref}")
    for v in data.get("Variations", []) or []:
        if isinstance(v, dict):
            check_enum(errors, f"{rel}: Variations.Status (leading token)",
                       leading_token(v.get("Status")) if v.get("Status") else None,
                       VARIATION_STATUS)
    for d in data.get("Detections", []) or []:
        if isinstance(d, dict):
            check_enum(errors, f"{rel}: Detections.Level", d.get("Level"), TIER)
            fp = d.get("ExpectedFPRate")
            if fp is not None and not FP_RATE_RE.match(str(fp)):
                errors.append(f"{rel}: Detections.ExpectedFPRate {fp!r} must start with "
                              f"Low/Medium/High (optionally 'Very ' or a range)")
            rule = d.get("SigmaRule")
            if rule and not (REPO / rule).exists():
                errors.append(f"{rel}: Detections.SigmaRule path does not exist: {rule}")
    for i in data.get("Intel", []) or []:
        if isinstance(i, dict):
            check_enum(errors, f"{rel}: Intel.Tier", i.get("Tier"), INTEL_TIER)

    # A draft research/hunt page needs more than a single source-specific
    # example before review. Two independently sourced variations are a modest
    # floor: they show the stated invariant survives a tool or campaign boundary
    # without turning the page into a claim of universal or actor-level
    # attribution. Keep this draft-only until the existing published corpus has
    # been remediated to the same standard.
    is_draft = rel_parts and rel_parts[0] == "drafts"
    if is_draft:
        source_variations = [
            variation for variation in (data.get("Variations", []) or [])
            if isinstance(variation, dict) and variation.get("Name") and variation.get("SourceURL")
        ]
        if len(source_variations) < 2:
            errors.append(
                f"{rel}: requires at least two variations with Name and SourceURL "
                "to support a publishable research/hunt chokepoint"
            )
        for index, variation in enumerate(data.get("Variations", []) or [], start=1):
            if not isinstance(variation, dict):
                errors.append(f"{rel}: Variations[{index}] is not a mapping")
                continue
            for field in ("Name", "FirstSeen", "Status", "SourceURL", "NotesShort", "Notes",
                          "VariantId", "ChokepointMapping"):
                if not variation.get(field):
                    errors.append(f"{rel}: Variations[{index}] missing draft-required field {field!r}")

    # directory <-> tactic consistency (the file's folder must be a declared tactic)
    # Drafts use drafts/<tactic>/<slug>/<entry>.yml while published entries use
    # chokepoints/<tactic>/<entry>.yml.  Resolve the tactic from the path rather
    # than assuming the file's parent is always the tactic directory.
    tactic_dir = rel_parts[1] if is_draft and len(rel_parts) >= 4 else path.parent.name
    expected = DIR_TO_TACTIC.get(tactic_dir)
    if expected is None:
        errors.append(f"{rel}: parent dir {tactic_dir!r} is not a known tactic directory")
    elif data.get("Tactics") and expected not in data["Tactics"]:
        errors.append(f"{rel}: folder implies tactic {expected!r} but Tactics={data.get('Tactics')}")

    return errors


def entry_paths(scope_arg: str | None) -> list[Path]:
    """Return YAML entries within an optional repository-relative scope.

    The default intentionally validates only published entries.  An explicit
    path is used by the draft/review workflow and must stay inside this repo so
    CI output remains reproducible.
    """
    if scope_arg is None:
        return sorted(CHOKEPOINTS_DIR.glob("*/*.yml"))

    scope = Path(scope_arg)
    if not scope.is_absolute():
        scope = REPO / scope
    scope = scope.resolve()
    try:
        scope.relative_to(REPO)
    except ValueError as exc:
        raise ValueError("scope must be inside the repository") from exc

    if scope.is_file():
        if scope.suffix.lower() not in {".yml", ".yaml"}:
            raise ValueError("scope file must be YAML")
        return [scope]
    if scope.is_dir():
        paths = sorted(
            path for pattern in ("*.yml", "*.yaml")
            for path in scope.rglob(pattern)
        )
        if paths:
            return paths
        raise ValueError("scope directory contains no YAML files")
    raise ValueError("scope does not exist")


# ── trends data validation ───────────────────────────────────────────────────
# The trends pages render from generated _data/*.yml files. A transform bug or a
# stray hand-edit that drops a section or emits a non-numeric count makes the page
# render blank or breaks the build. These specs assert the structure each template
# depends on: required meta keys, list sections, and the field types the templates
# do date/number work on. Add a page here when it goes data-driven.
_MISSING = object()
TYPE_DATE = "date"

TRENDS_SPECS = {
    "_data/edge_exploits.yml": {
        "meta": {"source": str, "generated": TYPE_DATE, "total_events": int,
                 "total_display": str, "date_range": str, "live_window": str},
        "sections": {
            "headline": {"key": str, "label": str, "count": int, "display": str},
            "targets": {"name": str, "count": int, "display": str},
            "daily": {"date": TYPE_DATE},
            "cves": {"id": str, "count": int},
        },
    },
    "_data/clickgrab_trends.yml": {
        "meta": {"source": str, "generated": TYPE_DATE, "date_range": str,
                 "total_reports": int, "total_sites_crawled": int, "total_malicious": int},
        "sections": {
            "daily": {"date": TYPE_DATE},
            "monthly": {"month": str},
            "staging_domains": {"domain": str, "count": int},
        },
    },
    "_data/masq_infra_hunts.yml": {
        "meta": {"generated": TYPE_DATE},
        "sections": {
            "campaigns": {"slug": str, "brand": str},
        },
    },
    "_data/edge_exploits_provenance.yml": {
        "meta": {"source": str, "generated": TYPE_DATE, "window": str,
                 "cumulative_unique_ips": int, "total_events": int},
        "sections": {
            "providers": {"name": str, "total": int},
            "asn_totals": {"name": str, "events": int},
        },
    },
}


def check_field(errors: list[str], label: str, value, typ) -> None:
    if value is _MISSING:
        errors.append(f"{label}: missing")
    elif typ == TYPE_DATE:
        if not DATE_RE.match(str(value)):
            errors.append(f"{label}: {value!r} is not ISO YYYY-MM-DD")
    elif typ is int:
        if not isinstance(value, int) or isinstance(value, bool):
            errors.append(f"{label}: {value!r} is not an integer")
    elif typ is str:
        if not isinstance(value, str) or not value:
            errors.append(f"{label}: {value!r} is not a non-empty string")


def validate_calendar_series(errors: list[str], label: str, rows: list[dict]) -> None:
    """Require a calendar chart to expose every date, including null-gap days.

    A missing date makes Chart.js place the preceding and following observations
    next to one another, concealing an acquisition gap. Date validation above is
    intentionally lightweight; this enforces the stronger time-series contract
    needed by the Edge Exploits charts.
    """
    previous: date | None = None
    for index, row in enumerate(rows):
        value = row.get("date") if isinstance(row, dict) else None
        try:
            current = date.fromisoformat(str(value))
        except ValueError:
            errors.append(f"{label}[{index}].date: {value!r} is not ISO YYYY-MM-DD")
            previous = None
            continue
        if previous is not None and current != previous + timedelta(days=1):
            errors.append(
                f"{label}[{index}].date: expected {(previous + timedelta(days=1)).isoformat()} "
                f"after {previous.isoformat()}, got {current.isoformat()}"
            )
        previous = current


def validate_edge_exploit_charts(data: dict, rel: str) -> list[str]:
    """Validate the time-series shape the three Edge Exploits charts require."""
    errors: list[str] = []

    daily = data.get("daily")
    if isinstance(daily, list):
        validate_calendar_series(errors, f"{rel}: daily", daily)

    recon = data.get("exploit_recon")
    recon_daily = recon.get("daily") if isinstance(recon, dict) else None
    if not isinstance(recon_daily, list):
        errors.append(f"{rel}: exploit_recon.daily must be a list")
    else:
        validate_calendar_series(errors, f"{rel}: exploit_recon.daily", recon_daily)
        for index, row in enumerate(recon_daily):
            for field in ("exploit", "recon"):
                value = row.get(field) if isinstance(row, dict) else None
                if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
                    errors.append(f"{rel}: exploit_recon.daily[{index}].{field} must be an integer or null")

    cb2 = data.get("cb2_daily")
    if not isinstance(cb2, dict):
        errors.append(f"{rel}: cb2_daily must be a mapping")
        return errors
    dates = cb2.get("dates")
    labels = cb2.get("labels")
    values = cb2.get("data")
    if not all(isinstance(item, list) for item in (dates, labels, values)):
        errors.append(f"{rel}: cb2_daily dates, labels, and data must be lists")
        return errors
    if not (len(dates) == len(labels) == len(values)):
        errors.append(f"{rel}: cb2_daily dates, labels, and data must have matching lengths")
        return errors
    validate_calendar_series(errors, f"{rel}: cb2_daily", [{"date": value} for value in dates])
    for index, value in enumerate(values):
        if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
            errors.append(f"{rel}: cb2_daily.data[{index}] must be an integer or null")
    return errors


def validate_edge_exploit_provenance(data: dict, rel: str) -> list[str]:
    """Require every plotted provider series to align with the month labels."""
    errors: list[str] = []
    labels = data.get("month_labels")
    providers = data.get("providers")
    if not isinstance(labels, list) or not labels or not all(isinstance(label, str) and label for label in labels):
        errors.append(f"{rel}: month_labels must be a non-empty list of strings")
        return errors
    if not isinstance(providers, list):
        return errors
    for index, provider in enumerate(providers):
        series = provider.get("series") if isinstance(provider, dict) else None
        if not isinstance(series, list):
            errors.append(f"{rel}: providers[{index}].series must be a list")
            continue
        if len(series) != len(labels):
            errors.append(
                f"{rel}: providers[{index}].series has {len(series)} values for {len(labels)} month labels"
            )
        for value_index, value in enumerate(series):
            if not isinstance(value, int) or isinstance(value, bool):
                errors.append(f"{rel}: providers[{index}].series[{value_index}] must be an integer")
    return errors


def validate_trends(rel: str, spec: dict) -> list[str]:
    errors: list[str] = []
    try:
        data = yaml.safe_load((REPO / rel).read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"{rel}: YAML parse error: {exc}"]
    if not isinstance(data, dict):
        return [f"{rel}: top-level YAML is not a mapping"]

    meta = data.get("meta")
    if not isinstance(meta, dict):
        errors.append(f"{rel}: missing 'meta' mapping")
    else:
        for key, typ in spec["meta"].items():
            check_field(errors, f"{rel}: meta.{key}", meta.get(key, _MISSING), typ)

    for section, elem in spec.get("sections", {}).items():
        val = data.get(section, _MISSING)
        if val is _MISSING:
            errors.append(f"{rel}: missing section {section!r}")
        elif not isinstance(val, list):
            errors.append(f"{rel}: section {section!r} must be a list")
        else:
            for i, item in enumerate(val):
                if not isinstance(item, dict):
                    errors.append(f"{rel}: {section}[{i}] is not a mapping")
                    continue
                for key, typ in elem.items():
                    check_field(errors, f"{rel}: {section}[{i}].{key}",
                                item.get(key, _MISSING), typ)

    if rel == "_data/edge_exploits.yml":
        errors.extend(validate_edge_exploit_charts(data, rel))
    elif rel == "_data/edge_exploits_provenance.yml":
        errors.extend(validate_edge_exploit_provenance(data, rel))
    return errors


def main() -> int:
    if len(sys.argv) > 2:
        print("usage: validate_schema.py [path-to-entry-or-directory]", file=sys.stderr)
        return 2

    scope_arg = sys.argv[1] if len(sys.argv) == 2 else None
    try:
        chokepoints = entry_paths(scope_arg)
    except ValueError as exc:
        print(f"[FAIL] invalid validation scope: {exc}", file=sys.stderr)
        return 2

    all_errors: list[str] = []
    for path in chokepoints:
        all_errors.extend(validate_entry(path))

    # Trends are global generated assets, so only validate them for the default
    # full-site run.  A scoped draft validation should not fail on unrelated
    # generated data or misleadingly report it as part of the draft.
    trends: list[str] = []
    if scope_arg is None:
        trends = [rel for rel in TRENDS_SPECS if (REPO / rel).exists()]
        for rel in trends:
            all_errors.extend(validate_trends(rel, TRENDS_SPECS[rel]))

    scope = f"{len(chokepoints)} chokepoint file(s)"
    if scope_arg is None:
        scope += f" and {len(trends)} trends data file(s)"
    if all_errors:
        print(f"\n  {len(all_errors)} error(s) across {scope}:\n")
        for e in all_errors:
            print(f"  [FAIL] {e}")
        print()
        return 1

    print(f"[OK] {scope} valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
