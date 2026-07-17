#!/usr/bin/env python3
"""Deterministic regression gates for promoted chokepoints.

The validation receipt contains outcomes and hashes only. Raw telemetry remains in
the lab lifecycle and is never committed to the repository.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


class RegressionError(ValueError):
    """Raised when a chokepoint no longer satisfies its regression contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RegressionError(message)


def unknown_paths(value: Any, path: str = "root") -> list[str]:
    hits: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            hits.extend(unknown_paths(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            hits.extend(unknown_paths(child, f"{path}[{index}]"))
    elif isinstance(value, str) and "<UNKNOWN" in value.upper():
        hits.append(path)
    return hits


def sha256_file(path: Path) -> str:
    # Git may materialize the same tracked file as LF or CRLF depending on the
    # checkout platform. Pin rule content, not an operating-system line ending.
    normalized = path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def locate_chokepoint(repo: Path, slug: str) -> Path:
    matches = list((repo / "chokepoints").rglob(f"{slug}.yml"))
    require(len(matches) == 1, f"expected one chokepoint for {slug}, found {len(matches)}")
    return matches[0]


def load_chokepoint(repo: Path, slug: str) -> tuple[Path, dict[str, Any]]:
    path = locate_chokepoint(repo, slug)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    require(isinstance(data, dict), f"{path} did not parse as a mapping")
    return path, data


def validate_contract_data(data: dict[str, Any], repo: Path) -> dict[str, str]:
    hits = unknown_paths(data)
    require(not hits, f"unknown placeholders remain at: {', '.join(hits)}")

    variations = data.get("Variations") or []
    require(len(variations) >= 2, "a promoted chokepoint needs at least two variations")
    required_variation = ("Name", "SourceURL", "VariantId", "ChokepointMapping")
    for index, variation in enumerate(variations):
        for field in required_variation:
            require(variation.get(field), f"variation {index + 1} is missing {field}")
        require(
            str(variation["SourceURL"]).startswith(("http://", "https://")),
            f"variation {index + 1} has a non-HTTP source",
        )
    source_urls = {str(item["SourceURL"]) for item in variations}
    require(len(source_urls) >= 2, "variations must be grounded by at least two source URLs")
    source_hosts = {urlparse(url).hostname for url in source_urls}
    require(len(source_hosts - {None}) >= 2, "variations must be grounded by at least two source hosts")
    variant_ids = [str(item["VariantId"]) for item in variations]
    require(len(variant_ids) == len(set(variant_ids)), "VariantId values must be unique")

    stages = data.get("Chokepoints") or []
    require(stages, "at least one chokepoint stage is required")
    for index, stage in enumerate(stages):
        for field in ("Stage", "Invariant", "Observable", "WhyCantBypass", "LogSources"):
            require(stage.get(field), f"chokepoint stage {index + 1} is missing {field}")

    detections = data.get("Detections") or []
    by_level = {str(item.get("Level", "")).lower(): item for item in detections}
    require(set(by_level) == {"research", "hunt", "analyst"}, "expected exactly Research, Hunt, and Analyst detections")
    hashes: dict[str, str] = {}
    for level in ("research", "hunt", "analyst"):
        detection = by_level[level]
        sigma_ref = detection.get("SigmaRule")
        require(sigma_ref, f"{level} detection is missing SigmaRule")
        sigma_path = repo / str(sigma_ref)
        require(sigma_path.is_file(), f"{level} Sigma file does not exist: {sigma_ref}")
        text = sigma_path.read_text(encoding="utf-8")
        require("<UNKNOWN" not in text.upper(), f"{level} Sigma contains an unknown placeholder")
        require("condition:" in text and "detection:" in text, f"{level} Sigma lacks detection logic")
        hashes[sigma_path.name] = sha256_file(sigma_path)

    pivots = data.get("OsintSources") or []
    require(pivots, "at least one OSINT pivot is required")
    for index, pivot in enumerate(pivots):
        for field in ("Platform", "Query", "URL", "Notes"):
            require(pivot.get(field), f"OSINT pivot {index + 1} is missing {field}")
        require(str(pivot["URL"]).startswith("https://"), f"OSINT pivot {index + 1} must use HTTPS")

    return hashes


def validate_contract(repo: Path, slug: str) -> tuple[dict[str, Any], dict[str, str]]:
    _, data = load_chokepoint(repo, slug)
    return data, validate_contract_data(data, repo)


def validate_receipt_data(
    data: dict[str, Any], hashes: dict[str, str], receipt: dict[str, Any]
) -> None:
    mitre_ids = {str(value).upper() for value in data.get("MitreIds") or []}
    require(receipt.get("schema_version") == "ValidationResult/v1", "unexpected validation receipt schema")
    require(str(receipt.get("tid", "")).upper() in mitre_ids, "receipt ATT&CK ID is not on the chokepoint")
    require(receipt.get("mode") == "telemetry", "receipt must come from telemetry validation")
    require(receipt.get("telemetry_observed") is True, "receipt does not confirm telemetry")
    require(receipt.get("sweep_passed") is True, "validation sweep did not pass")
    require(int(receipt.get("event_count", 0)) > 0, "validation receipt has no events")

    tier_rows = receipt.get("tiers") or []
    receipt_hashes = {row.get("file"): row.get("sigma_sha256") for row in tier_rows}
    require(receipt_hashes == hashes, "validation receipt does not match the current Sigma hashes")

    cases = receipt.get("cases") or []
    require(len(cases) >= 3, "validation sweep needs positive, hunt-only, and negative cases")
    require(sum(int(row.get("event_count", 0)) for row in cases) == int(receipt["event_count"]), "case event counts do not sum to the receipt total")

    analyst_positive = 0
    hunt_only = 0
    research_only = 0
    for case in cases:
        require(case.get("case_id"), "validation case is missing case_id")
        require(case.get("passed") is True, f"validation case failed: {case.get('case_id')}")
        rows = {row.get("file"): row for row in case.get("tiers") or []}
        require(set(rows) == set(hashes), f"case {case['case_id']} does not cover every tier")
        for filename, row in rows.items():
            require(row.get("sigma_sha256") == hashes[filename], f"case {case['case_id']} has a stale {filename} hash")
            require(row.get("pass") is True, f"case {case['case_id']} failed {filename}")
            require(row.get("actual") == row.get("expected"), f"case {case['case_id']} changed outcome for {filename}")
        analyst = bool(rows["analyst.yml"]["expected"])
        hunt = bool(rows["hunt.yml"]["expected"])
        research = bool(rows["research.yml"]["expected"])
        require(research, f"case {case['case_id']} must exercise the Research baseline")
        analyst_positive += int(analyst and hunt)
        hunt_only += int(hunt and not analyst)
        research_only += int(not hunt and not analyst)

    require(analyst_positive >= 2, "sweep needs at least two Analyst-positive variations")
    require(hunt_only >= 1, "sweep needs at least one Hunt-only variation")
    require(research_only >= 1, "sweep needs at least one legitimate/neutral control")


def validate_rendered_page(repo: Path, slug: str, data: dict[str, Any]) -> Path:
    page = repo / "_site" / "chokepoints" / slug / "index.html"
    require(page.is_file(), f"rendered page not found: {page}; run aggregate.py and Jekyll first")
    rendered = page.read_text(encoding="utf-8")
    for level in ("Research", "Hunt", "Analyst"):
        require(rendered.count(f"Sigma Rule - {level} Level") == 1, f"rendered page must show one {level} tier")
    for variation in data.get("Variations") or []:
        require(html.escape(str(variation["Name"])) in rendered, f"rendered page is missing {variation['Name']}")
    for pivot in data.get("OsintSources") or []:
        require(html.escape(str(pivot["URL"]), quote=True) in rendered, f"rendered page is missing OSINT URL {pivot['URL']}")
    require('id="osint-pivots"' in rendered, "rendered page is missing the OSINT section")
    require("<UNKNOWN" not in rendered.upper(), "rendered page contains an unknown placeholder")
    return page


def load_receipt(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(data, dict), "validation receipt must be a JSON object")
    return data


def run(repo: Path, slug: str, receipt_path: Path, check_site: bool) -> dict[str, Any]:
    data, hashes = validate_contract(repo, slug)
    receipt = load_receipt(receipt_path)
    validate_receipt_data(data, hashes, receipt)
    page = validate_rendered_page(repo, slug, data) if check_site else None
    return {
        "slug": slug,
        "variations": len(data.get("Variations") or []),
        "osint_pivots": len(data.get("OsintSources") or []),
        "cases": len(receipt.get("cases") or []),
        "tier_outcomes": sum(len(row.get("tiers") or []) for row in receipt.get("cases") or []),
        "sigma_hashes": hashes,
        "rendered_page": str(page) if page else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--slug", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--check-site", action="store_true")
    args = parser.parse_args()
    try:
        result = run(args.repo.resolve(), args.slug, args.receipt.resolve(), args.check_site)
    except (OSError, ValueError, yaml.YAMLError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 1
    print(json.dumps({"ok": True, **result}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
