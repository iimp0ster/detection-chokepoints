"""Verify the five pilot atomics with scoped field examples and the Sigma parser."""
import argparse
from collections import Counter
import json
from pathlib import Path
from uuid import UUID

from jsonschema import Draft202012Validator
from sigma.collection import SigmaCollection
import yaml

from validate_defensive_coverage import public_reference

ROOT = Path(__file__).resolve().parents[1]
SLUG = "container-escape-variations"
BUNDLE = ROOT / "sigma-rules" / SLUG


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def fixture_match(selection, fields):
    """Check only the equality and literal-suffix expressions used by these fixtures."""
    for expression, expected in selection.items():
        field, *modifiers = expression.split("|")
        actual = fields.get(field)
        if modifiers == ["endswith", "cased"]:
            if not isinstance(actual, str) or not actual.endswith(expected):
                return False
        elif modifiers in ([], ["cased"]):
            if type(actual) is not type(expected) or actual != expected:
                return False
        else:
            raise ValueError(f"Unexpected fixture expression {expression}")
    return True


def validate(schema_path=None, check_site=False):
    index = yaml.safe_load((ROOT / "_data/defensive_coverage_profiles.yml").read_text(encoding="utf-8"))
    assert {slug: entry["sigma_bundle"] for slug, entry in index.items() if "sigma_bundle" in entry} == {SLUG: SLUG}
    bundle = yaml.safe_load((ROOT / "_data/container_escape_sigma.yml").read_text(encoding="utf-8"))
    assert bundle["format"] == "container-escape-sigma/v1" and bundle["backend_note"]
    cards = {item["id"]: item for item in bundle["rules"]}
    assert len(cards) == len(bundle["rules"]) == 5
    assert {p.stem for p in BUNDLE.glob("*.yml")} == cards.keys()
    profile = read_json(ROOT / index[SLUG]["telemetry_value"].lstrip("/"))
    variants = {v["id"]: v for v in profile["variations"]}
    cells = {(c["variation"], c["row"]): c for c in profile["relevanceMatrix"]["cells"]}
    prior = read_json(ROOT / index[SLUG]["profile"].lstrip("/"))
    examples = {x["id"]: x for x in prior["evidenceExamples"]}
    schema = Draft202012Validator(read_json(schema_path)) if schema_path else None
    parsed = {}
    ids = set()
    for name, card in cards.items():
        source = BUNDLE / (name + ".yml")
        raw = source.read_text(encoding="utf-8")
        rule = yaml.safe_load(raw)
        if schema:
            schema.validate(rule)
        collection = SigmaCollection.from_yaml(raw)
        assert not collection.errors and len(collection.rules) == 1
        assert set(rule) == {
            "title", "id", "status", "description", "references", "author", "date",
            "tags", "logsource", "detection", "falsepositives", "level"
        }
        assert UUID(rule["id"]).version == 4 and rule["id"] not in ids
        ids.add(rule["id"])
        assert rule["title"] == card["title"] and rule["description"] == card["rationale"]
        assert rule["status"] == "experimental" and "detection.maturity.research" in rule["tags"]
        assert rule["level"] == "low" and rule["falsepositives"] == card["administrative"]
        assert any(tag.startswith("attack.t") for tag in rule["tags"])
        # The accepted pilot intentionally baselines unsuppressed Research atomics.
        # Introduce a real exclusion only with evidence from authorized controls.
        assert set(rule["detection"]) == {"selection", "condition"} and rule["detection"]["condition"] == "selection"
        assert set(rule["references"]) == {ref["url"] for ref in card["sources"]}
        for ref in card["sources"]:
            assert public_reference(ref["url"]) and ref["locator"]
        assert all(card[key] for key in ("fields", "fragment", "origin", "next_evidence", "blind_spots", "validation"))
        assert (card["variation"], card["row"]) in cells
        assert card["requires"] and set(card["requires"]) <= set(variants[card["variation"]]["capabilities"])
        parsed[name] = rule["detection"]["selection"]
        assert card["matches"] == [f"{key}: {value}" for key, value in parsed[name].items()]
        assert all(card[key] for key in ("backend_mapping", "hunt_gate", "analyst_gate"))
        if check_site:
            asset = ROOT / "_site/assets/sigma" / SLUG / source.name
            assert asset.read_bytes() == source.read_bytes(), f"rule asset drift {name}"

    cases = read_json(ROOT / "scripts/fixtures/container-escape-sigma-cases.json")
    assert len(cases) == len({(item["rule"], item["id"]) for item in cases}) == 22
    assert sum(item["basis"] == "benign-illustrative" and item["match"] for item in cases) == 5
    assert sum(item["basis"] == "measured-native" and item["match"] for item in cases) == 1
    results = Counter()
    for sample in cases:
        fields = sample["fields"]
        if retained := sample.get("approved_evidence"):
            example = examples[retained]
            assert example["provenance"] == "native-projection"
            assert sample["basis"] == "measured-native" and fields is None
            fields = {value["field"]: value["value"] for value in example["fields"] if value["field"] == "topic"}
            assert fields == {"topic": "/tasks/start"}
        assert (fields is not None and fixture_match(parsed[sample["rule"]], fields)) is sample["match"], sample["id"]
        result = "match" if sample["match"] else "no match"
        results[(sample["rule"], result)] += 1
        print(f"{sample['rule']}  {sample['id']}  {sample['basis']}  {result}")
    assert all(results[(name, outcome)] for name in cards for outcome in ("match", "no match"))
    if check_site:
        catalog = ROOT / "_site/chokepoints"
        for page in catalog.glob("*/index.html"):
            mounted = 'id="container-escape-sigma"' in page.read_text(encoding="utf-8")
            assert mounted == (page.parent.name == SLUG)
    print(f"{len(cards)} Sigma Research atomics, {len(cases)} scoped cases passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema", type=Path, help="Optional local copy of the official Sigma detection schema")
    parser.add_argument("--check-site", action="store_true")
    args = parser.parse_args()
    validate(args.schema, args.check_site)

