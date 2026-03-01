#!/usr/bin/env python3
"""
Pre-build script for the Detection Chokepoints Jekyll site.

Reads YAML entries from chokepoints/<tactic>/*.yml, reads matching sigma rule
files from sigma-rules/<dir>/{research,hunt,analyst}.yml, and generates:

  - _data/chokepoints.yml        (Jekyll data layer for Liquid templates)
  - assets/js/search-index.json  (Fuse.js client-side search index)
  - _chokepoints/<slug>.md       (Jekyll collection stubs, one per chokepoint)

Run before `jekyll build`. The GitHub Actions workflow does this automatically.
"""

import glob
import json
import os
import re
import sys

import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHOKEPOINTS_GLOB = os.path.join(REPO_ROOT, "chokepoints", "*", "*.yml")
SIGMA_RULES_DIR = os.path.join(REPO_ROOT, "sigma-rules")
DATA_DIR = os.path.join(REPO_ROOT, "_data")
COLLECTION_DIR = os.path.join(REPO_ROOT, "_chokepoints")
ASSETS_JS_DIR = os.path.join(REPO_ROOT, "assets", "js")
SIGMA_LEVELS = ("research", "hunt", "analyst")


def extract_sigma_dir(detections):
    """Derive the sigma-rules sub-directory from the first SigmaRule path.

    e.g. "sigma-rules/clickfix/research.yml" -> "clickfix"
    """
    for det in detections or []:
        rule_path = det.get("SigmaRule", "")
        if rule_path:
            parts = rule_path.replace("\\", "/").split("/")
            if len(parts) >= 2:
                return parts[1]
    return None


def read_sigma_rules(sigma_dir):
    """Return a dict mapping level -> raw YAML text (or None if file missing)."""
    rules = {}
    if not sigma_dir:
        return rules
    for level in SIGMA_LEVELS:
        path = os.path.join(SIGMA_RULES_DIR, sigma_dir, f"{level}.yml")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                rules[level] = fh.read()
        else:
            rules[level] = None
    return rules


def load_chokepoints():
    """Load, enrich, and return all chokepoint entries as a list of dicts."""
    entries = []
    for path in sorted(glob.glob(CHOKEPOINTS_GLOB)):
        tactic = os.path.basename(os.path.dirname(path))
        slug = os.path.splitext(os.path.basename(path))[0]

        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)

        if not data or not isinstance(data, dict):
            print(f"Warning: skipping empty/invalid YAML at {path}", file=sys.stderr)
            continue

        # Computed fields (prefixed with _ so contributors know they're generated)
        data["_tactic"] = tactic
        data["_slug"] = slug
        data["_source_path"] = os.path.relpath(path, REPO_ROOT)

        sigma_dir = extract_sigma_dir(data.get("Detections", []))
        data["_sigma_dir"] = sigma_dir
        sigma_rules = read_sigma_rules(sigma_dir)
        for level in SIGMA_LEVELS:
            data[f"_sigma_{level}"] = sigma_rules.get(level)

        # Flatten text fields for search index
        prereqs = data.get("Prerequisites", []) or []
        data["_prerequisites_text"] = " ".join(str(p) for p in prereqs)

        variations = data.get("Variations", []) or []
        data["_variation_names"] = " ".join(
            str(v.get("Name", "")) for v in variations if isinstance(v, dict)
        )

        entries.append(data)

    return entries


def write_data_file(entries):
    """Write _data/chokepoints.yml for Jekyll Liquid templates."""
    os.makedirs(DATA_DIR, exist_ok=True)
    out_path = os.path.join(DATA_DIR, "chokepoints.yml")
    with open(out_path, "w", encoding="utf-8") as fh:
        yaml.dump(entries, fh, default_flow_style=False, allow_unicode=True,
                  sort_keys=False)
    print(f"  Wrote {os.path.relpath(out_path, REPO_ROOT)} ({len(entries)} entries)")


def write_search_index(entries):
    """Write assets/js/search-index.json as a lean JSON array for Fuse.js."""
    os.makedirs(ASSETS_JS_DIR, exist_ok=True)
    index = []
    for e in entries:
        index.append({
            "id": e.get("Id", ""),
            "name": e.get("Name", ""),
            "slug": e["_slug"],
            "tactic": e["_tactic"],
            "tactics": e.get("Tactics", []),
            "mitreIds": e.get("MitreIds", []),
            "detectionPriority": e.get("DetectionPriority", ""),
            "threatPrevalence": e.get("ThreatPrevalence", ""),
            "detectionDifficulty": e.get("DetectionDifficulty", ""),
            "description": (e.get("Description") or "").strip(),
            "prerequisites": e.get("_prerequisites_text", ""),
            "variationNames": e.get("_variation_names", ""),
        })
    out_path = os.path.join(ASSETS_JS_DIR, "search-index.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=2)
    print(f"  Wrote {os.path.relpath(out_path, REPO_ROOT)} ({len(index)} entries)")


def write_collection_stubs(entries):
    """Write _chokepoints/<slug>.md — thin Jekyll collection stubs."""
    os.makedirs(COLLECTION_DIR, exist_ok=True)
    for e in entries:
        stub_path = os.path.join(COLLECTION_DIR, f"{e['_slug']}.md")
        front = {
            "layout": "chokepoint",
            "slug": e["_slug"],
            "title": e.get("Name", e["_slug"]),
        }
        content = "---\n" + yaml.dump(front, default_flow_style=False) + "---\n"
        with open(stub_path, "w", encoding="utf-8") as fh:
            fh.write(content)
    print(f"  Wrote {len(entries)} stub files to _chokepoints/")


if __name__ == "__main__":
    print("Aggregating chokepoint data...")
    entries = load_chokepoints()
    print(f"  Loaded {len(entries)} chokepoints")
    write_data_file(entries)
    write_search_index(entries)
    write_collection_stubs(entries)
    print("Done.")
