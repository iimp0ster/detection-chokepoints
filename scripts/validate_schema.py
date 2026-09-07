#!/usr/bin/env python3
"""Validate chokepoint YAML entries against schema/chokepoint-schema.yml, plus the
generated trends data files (_data/*.yml) against the structure their page
templates depend on.

Run locally or in CI: `python scripts/validate_schema.py`
Exits non-zero if any entry has errors, so it can gate a pull request.

Why a standalone validator rather than a JSON-Schema file: the chokepoint
schema mixes simple enums with cross-file invariants (Sigma paths must exist on
disk, the parent directory must match a declared tactic). Those checks are
clearer in code than in a declarative schema, and the error messages can point
at the exact file and field a contributor needs to fix.
"""
from __future__ import annotations

import argparse
import re
import sys
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
OPPORTUNITY_FIELDS = ("Category", "Objective", "Placement", "Signal", "SafetyBoundary", "Validation")

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
# Draft entries mark a field that cannot be grounded from cited intel as
# "<UNKNOWN -- verify against lab data>" (the cp-drafter anti-fabrication rule). That is a
# legitimate DRAFT state, not a schema error — enum/format checks skip it, and it is counted
# instead so a human sees the entry is not promotion-ready (a promoted chokepoints/ entry
# should carry zero placeholders; the count surfaces any that slip through).
UNKNOWN_RE = re.compile(r"^\s*<UNKNOWN", re.I)


def _is_unknown(value) -> bool:
    return isinstance(value, str) and bool(UNKNOWN_RE.match(value))

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
    if value is not None and not _is_unknown(value) and value not in allowed:
        errors.append(f"{label}: {value!r} is not one of {sorted(allowed)}")


def leading_token(value: str) -> str:
    """First word of an authored status string, e.g. 'Disrupted (Oct 2024)' -> 'Disrupted'."""
    return re.split(r"[\s(/-]", value.strip(), maxsplit=1)[0] if isinstance(value, str) else value


def _under_repo(path: Path) -> bool:
    try:
        path.relative_to(REPO)
        return True
    except ValueError:
        return False


def _resolve_tactic_dir(path: Path) -> str:
    """The directory that names the entry's tactic.

    Canonical entries live at `chokepoints/<tactic>/<file>.yml` — the parent dir IS
    the tactic. Draft entries add a slug level: `drafts/<tactic>/<slug>/<file>.yml`,
    so the tactic is the segment directly under `drafts/`, not the immediate parent.
    """
    try:
        parts = path.relative_to(REPO).parts
    except ValueError:
        parts = path.parts
    if len(parts) >= 3 and parts[0] == "drafts":
        return parts[1]
    return path.parent.name


def _looks_like_sigma(data: dict) -> bool:
    """A Sigma rule file (title/detection/logsource) is not a chokepoint entry.
    A directory scan of a draft picks up its sigma/*.yml alongside the chokepoint
    YAML; skip those here (they're validated by Sigma tooling, not this schema)."""
    return ("detection" in data and "logsource" in data
            and "MitreIds" not in data and "Name" not in data)


def validate_clickfix_page_standard(errors: list[str], rel: str, data: dict) -> None:
    """Gate future drafts against the complete live ClickFix page contract.

    This is intentionally stricter than basic YAML validation.  A new public
    chokepoint must be reviewable end-to-end: the renderer should never hide a
    missing prevention, validation, emulation, OSINT, or relationship section
    just because a draft supplied only stages and Sigma stubs.
    """
    description = data.get("Description")
    if not isinstance(description, str) or len(description.strip()) < 120:
        errors.append(f"{rel}: ClickFix page standard Description must concretely explain the attacker behavior and required environmental contact (at least 120 characters)")

    stages = data.get("Chokepoints") or []
    if not isinstance(stages, list) or len(stages) < 3:
        errors.append(f"{rel}: ClickFix page standard requires at least 3 Chokepoints stages")
    else:
        for idx, stage in enumerate(stages, start=1):
            if not isinstance(stage, dict):
                errors.append(f"{rel}: ClickFix page standard Chokepoints[{idx}] must be a mapping")
                continue
            for field in ("Stage", "Input", "Invariant", "Observable", "WhyCantBypass", "LogSources", "DetectionTier", "SigmaRef"):
                if stage.get(field) in (None, "", [], {}):
                    errors.append(f"{rel}: ClickFix page standard Chokepoints[{idx}].{field} is required")

    variations = data.get("Variations") or []
    for idx, variation in enumerate(variations, start=1):
        if not isinstance(variation, dict):
            continue
        for field in ("FirstSeen", "Status", "Notes", "Command"):
            if variation.get(field) in (None, "", [], {}):
                errors.append(f"{rel}: ClickFix page standard Variations[{idx}].{field} is required")
        command = variation.get("Command")
        if isinstance(command, dict) and not any(command.get(field) not in (None, "", [], {}) for field in ("Context", "Invocation", "Artifacts")):
            errors.append(f"{rel}: ClickFix page standard Variations[{idx}].Command needs Context, Invocation, or Artifacts")

    detections = data.get("Detections") or []
    by_level = {str(row.get("Level", "")).strip().lower(): row for row in detections if isinstance(row, dict)}
    for level in ("research", "hunt", "analyst"):
        row = by_level.get(level)
        if not row:
            errors.append(f"{rel}: ClickFix page standard requires a {level.title()} Detection")
        elif row.get("SigmaRule") in (None, ""):
            errors.append(f"{rel}: ClickFix page standard {level.title()} Detection requires SigmaRule")

    if not data.get("PreventionSummary"):
        errors.append(f"{rel}: ClickFix page standard requires PreventionSummary")
    opportunities = data.get("PreventionOpportunities") or []
    if not isinstance(opportunities, list) or not opportunities:
        errors.append(f"{rel}: ClickFix page standard requires at least one PreventionOpportunity")
    else:
        for idx, opportunity in enumerate(opportunities, start=1):
            if not isinstance(opportunity, dict):
                errors.append(f"{rel}: PreventionOpportunities[{idx}] must be a mapping")
                continue
            for field in ("Category", "Control", "Impact"):
                if opportunity.get(field) in (None, "", [], {}):
                    errors.append(f"{rel}: ClickFix page standard PreventionOpportunities[{idx}].{field} is required")

    raw_logs = data.get("RawLogs") or []
    if not isinstance(raw_logs, list) or not raw_logs:
        errors.append(f"{rel}: ClickFix page standard requires at least one RawLogs sample")
    else:
        for idx, raw_log in enumerate(raw_logs, start=1):
            if not isinstance(raw_log, dict):
                errors.append(f"{rel}: RawLogs[{idx}] must be a mapping")
                continue
            for field in ("Type", "Description", "EvidenceBasis", "SourceURL", "MatchedRules", "Sample"):
                if raw_log.get(field) in (None, "", [], {}):
                    errors.append(f"{rel}: ClickFix page standard RawLogs[{idx}].{field} is required")
            matched = {str(value).strip().casefold() for value in (raw_log.get("MatchedRules") or [])}
            if not {"research", "hunt", "analyst"}.issubset(matched):
                errors.append(f"{rel}: RawLogs[{idx}].MatchedRules must identify Research, Hunt, and Analyst coverage")

        raw_log_sources = {
            str(row.get("SourceURL", "")).strip()
            for row in raw_logs if isinstance(row, dict) and row.get("SourceURL")
        }
        for idx, variation in enumerate(variations, start=1):
            if isinstance(variation, dict) and str(variation.get("SourceURL", "")).strip() not in raw_log_sources:
                errors.append(f"{rel}: Variations[{idx}] needs a source-matched RawLogs sample")

    emulation = data.get("EmulationScript")
    if not isinstance(emulation, dict):
        errors.append(f"{rel}: ClickFix page standard requires a fixed lab-only EmulationScript")
    else:
        for field in ("AtomicRef", "Description", "File", "Language", "SafetyNotes"):
            if emulation.get(field) in (None, "", [], {}):
                errors.append(f"{rel}: ClickFix page standard EmulationScript.{field} is required")
        emulation_file = emulation.get("File")
        if isinstance(emulation_file, str):
            resolved = (REPO / emulation_file).resolve()
            if REPO.resolve() not in resolved.parents or not resolved.is_file():
                errors.append(f"{rel}: ClickFix page standard EmulationScript.File must resolve to an existing repository file")

    osint = data.get("OsintSources") or []
    if not isinstance(osint, list) or not osint:
        errors.append(f"{rel}: ClickFix page standard requires at least one OsintSources pivot")
    else:
        for idx, pivot in enumerate(osint, start=1):
            if not isinstance(pivot, dict):
                errors.append(f"{rel}: OsintSources[{idx}] must be a mapping")
                continue
            for field in ("Platform", "Query", "Notes", "URL"):
                if pivot.get(field) in (None, "", [], {}):
                    errors.append(f"{rel}: ClickFix page standard OsintSources[{idx}].{field} is required")
            url = pivot.get("URL")
            if url not in (None, "", [], {}) and (not isinstance(url, str) or not re.match(r"^https://[^\s]+$", url)):
                errors.append(f"{rel}: ClickFix page standard OsintSources[{idx}].URL must be a usable HTTPS destination")

    related = data.get("RelatedChokepoints") or []
    if not isinstance(related, list) or not any(isinstance(slug, str) and slug.strip() for slug in related):
        errors.append(f"{rel}: ClickFix page standard requires at least one RelatedChokepoints entry")


def validate_entry(path: Path) -> list[str]:
    errors: list[str] = []
    rel = path.relative_to(REPO).as_posix() if _under_repo(path) else path.as_posix()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"{rel}: YAML parse error: {exc}"]
    if not isinstance(data, dict):
        return [f"{rel}: top-level YAML is not a mapping"]
    if _looks_like_sigma(data):
        return []  # a Sigma rule, not a chokepoint entry — not this validator's job

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
            if ref and not isinstance(ref, str):
                errors.append(f"{rel}: Chokepoints.SigmaRef must be a string path, got {type(ref).__name__}")
            elif ref and not (REPO / ref).exists():
                errors.append(f"{rel}: Chokepoints.SigmaRef path does not exist: {ref}")
    variations = data.get("Variations", []) or []
    for v in variations:
        if isinstance(v, dict):
            check_enum(errors, f"{rel}: Variations.Status (leading token)",
                       leading_token(v.get("Status")) if v.get("Status") else None,
                       VARIATION_STATUS)

    # Promotion gate for NEW work. A chokepoint is only persuasive when the same
    # invariant is demonstrated across at least two distinct implementations.
    # Keep this draft-scoped so older canonical entries remain readable while
    # they are brought up to the stronger evidence standard; every future draft
    # must clear it before it can move out of drafts/.
    is_draft = rel.startswith("drafts/")
    if is_draft:
        if not isinstance(variations, list) or len(variations) < 2:
            errors.append(
                f"{rel}: promotion gate requires at least 2 distinct, source-grounded Variations"
            )
        for idx, variation in enumerate(variations, start=1):
            if not isinstance(variation, dict):
                errors.append(f"{rel}: Variations[{idx}] must be a mapping")
                continue
            for field in ("Name", "SourceURL", "ChokepointMapping"):
                value = variation.get(field)
                if value in (None, "", [], {}) or _is_unknown(value):
                    errors.append(
                        f"{rel}: Variations[{idx}].{field} is required and must be source-grounded for promotion"
                    )
        names = [str(v.get("Name", "")).strip().casefold()
                 for v in variations if isinstance(v, dict) and v.get("Name")]
        if len(names) != len(set(names)):
            errors.append(
                f"{rel}: promotion gate requires distinct Variations; duplicate Name values do not count"
            )
        # New public entries use the fully populated ClickFix page as the
        # operator-facing standard.  Older canonical pages are intentionally
        # exempt while they are backfilled; every future draft must satisfy it
        # before promotion can copy it into chokepoints/.
        validate_clickfix_page_standard(errors, rel, data)
    for d in data.get("Detections", []) or []:
        if isinstance(d, dict):
            check_enum(errors, f"{rel}: Detections.Level", d.get("Level"), TIER)
            fp = d.get("ExpectedFPRate")
            if fp is not None and not _is_unknown(fp) and not FP_RATE_RE.match(str(fp)):
                errors.append(f"{rel}: Detections.ExpectedFPRate {fp!r} must start with "
                              f"Low/Medium/High (optionally 'Very ' or a range)")
            rule = d.get("SigmaRule")
            if rule and not isinstance(rule, str):
                errors.append(f"{rel}: Detections.SigmaRule must be a string path, got {type(rule).__name__}")
            elif rule and not (REPO / rule).exists():
                errors.append(f"{rel}: Detections.SigmaRule path does not exist: {rule}")
    for i in data.get("Intel", []) or []:
        if isinstance(i, dict):
            check_enum(errors, f"{rel}: Intel.Tier", i.get("Tier"), INTEL_TIER)

    # Deception is intentionally optional, but a present entry must be a safe,
    # reviewable opportunity rather than an implied production deployment.
    if "DeceptionOpportunities" in data:
        opportunities = data.get("DeceptionOpportunities")
        if not isinstance(opportunities, list):
            errors.append(f"{rel}: DeceptionOpportunities must be a list")
        else:
            for idx, opportunity in enumerate(opportunities, start=1):
                if not isinstance(opportunity, dict):
                    errors.append(f"{rel}: DeceptionOpportunities[{idx}] must be a mapping")
                    continue
                for field in OPPORTUNITY_FIELDS:
                    value = opportunity.get(field)
                    if value in (None, "", [], {}) or (not is_draft and _is_unknown(value)):
                        errors.append(f"{rel}: DeceptionOpportunities[{idx}].{field} must be a grounded non-empty value")

    # directory <-> tactic consistency (the file's folder must be a declared tactic).
    # Resolves both chokepoints/<tactic>/ and drafts/<tactic>/<slug>/ layouts.
    tactic_dir = _resolve_tactic_dir(path)
    expected = DIR_TO_TACTIC.get(tactic_dir)
    if expected is None:
        errors.append(f"{rel}: parent dir {tactic_dir!r} is not a known tactic directory")
    elif data.get("Tactics") and expected not in data["Tactics"]:
        errors.append(f"{rel}: folder implies tactic {expected!r} but Tactics={data.get('Tactics')}")

    return errors


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
    "_data/masq_infra_trends.yml": {
        "meta": {
            "generated": TYPE_DATE,
            "schema_version": str,
            "observation_count": int,
            "endpoint_observation_count": int,
            "validated_cluster_count": int,
        },
        "sections": {
            "trust_surfaces": {"trust_surface": str, "count": int},
            "delivery_mechanisms": {"delivery_mechanism": str, "count": int},
            "osint_pivots": {"pivot": str, "count": int},
            "endpoint_handoffs": {"endpoint_handoff": str, "count": int},
            "observations": {"id": str, "evidence_tier": str, "source_url": str},
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
    return errors


def _collect(path_arg: str | None) -> list[Path]:
    """Files to validate. No arg → all canonical chokepoints (CI default). A file →
    just it. A directory → every *.yml under it (so `drafts/<tactic>/<slug>/` works)."""
    if path_arg is None:
        return sorted(CHOKEPOINTS_DIR.glob("*/*.yml"))
    p = Path(path_arg)
    if not p.is_absolute():
        p = Path.cwd() / p
    p = p.resolve()
    if p.is_file():
        return [p]
    if p.is_dir():
        return sorted(p.rglob("*.yml"))
    return []


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path", nargs="?", default=None,
                    help="optional .yml file or directory to validate "
                         "(e.g. drafts/<tactic>/<slug>/<slug>.yml); "
                         "default: all chokepoints/ + trends data files")
    args = ap.parse_args(argv)

    targets = _collect(args.path)
    if args.path is not None and not targets:
        print(f"[FAIL] path not found: {args.path}")
        return 1

    all_errors: list[str] = []
    placeholders: dict[str, int] = {}
    for path in targets:
        # fail-soft: a malformed entry (e.g. a list-typed SigmaRef) becomes a
        # reported finding, never an uncaught traceback that aborts the whole run.
        rel = path.relative_to(REPO).as_posix() if _under_repo(path) else path.as_posix()
        try:
            all_errors.extend(validate_entry(path))
            try:
                # count only the actual drafter marker ("<UNKNOWN -- verify ...>"), not
                # incidental "<UNKNOWN>" mentions in comments/prose.
                n = sum(1 for _ in re.finditer(r"<UNKNOWN\s*--\s*verify",
                                               path.read_text(encoding="utf-8"), re.I))
            except OSError:
                n = 0
            if n:
                placeholders[rel] = n
        except Exception as exc:  # noqa: BLE001 — deliberately broad; report, don't crash
            all_errors.append(f"{rel}: validator crashed on this entry: {type(exc).__name__}: {exc}")

    # Trends data files are validated only on the full (no-path) run — they aren't
    # chokepoint entries, so a targeted file/dir check shouldn't drag them in.
    trends: list[str] = []
    if args.path is None:
        trends = [rel for rel in TRENDS_SPECS if (REPO / rel).exists()]
        for rel in trends:
            all_errors.extend(validate_trends(rel, TRENDS_SPECS[rel]))

    scope = f"{len(targets)} entry file(s)" + (
        f" and {len(trends)} trends data file(s)" if args.path is None else "")

    def _report_placeholders() -> None:
        if not placeholders:
            return
        total = sum(placeholders.values())
        print(f"  [NOTE] {total} unresolved <UNKNOWN> placeholder(s) -- not promotion-ready "
              f"until grounded against lab data:")
        for rel, n in sorted(placeholders.items()):
            print(f"         {n:>3}  {rel}")
        print()

    if all_errors:
        print(f"\n  {len(all_errors)} error(s) across {scope}:\n")
        for e in all_errors:
            print(f"  [FAIL] {e}")
        print()
        _report_placeholders()
        return 1

    print(f"[OK] {scope} structurally valid.")
    _report_placeholders()
    return 0


if __name__ == "__main__":
    sys.exit(main())
