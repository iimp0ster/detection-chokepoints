"""Validate public defensive coverage profiles and the research-page index."""
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

from jsonschema import Draft202012Validator, ValidationError
import yaml

ROOT = Path(__file__).resolve().parents[1]
PILOT = "container-escape-variations"
PILOT_GRAPH_SHA256 = "6e2fa1f327f33bafb6e387aba261d3c15e30e36821505b2d59119ecd846ffc96"

SITE_PATH = re.compile(r"^/(?:[a-z0-9-]+/)*[a-z0-9-]+/$")
DATA_PATH = re.compile(r"^/assets/data/(?:[a-z0-9-]+/)*[a-z0-9-]+(?:\.[a-z0-9-]+)*\.json$")


def public_reference(value):
    url = urlsplit(value)
    if url.scheme != "https" or not url.hostname or url.username or url.password:
        return False
    if url.hostname.rstrip(".").lower() == "github.com":
        owner, *repository = unquote(url.path).strip("/").lower().split("/", 2)
        if owner == "iimp0ster":
            return repository[:1] == ["detection-chokepoints"]
    return True


def json_file(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def named(items, label):
    rows = {item["id"]: item for item in items}
    if len(rows) != len(items):
        raise ValueError(f"Duplicate {label} ID")
    return rows


def compatible(ids, inventory, label):
    unknown = set(ids) - inventory.keys()
    if unknown:
        raise ValueError(f"Unknown {label}: {', '.join(sorted(unknown))}")


def exact_pilot_counts(profile):
    findings = named(profile.get("findings", []), "finding")

    def receipt(finding_id):
        return [[(m["label"], m["confirmed"], m["denominator"]) for m in row["metrics"]]
                for row in findings[finding_id]["comparisons"]]

    if receipt("delegated-effect-v-cause") != [
        [("Downstream effects", 9, 9), ("Causal edges", 0, 7)],
        [("Downstream effects", 9, 9), ("Causal edges", 7, 7)],
    ]:
        raise ValueError("Gate C.2 delegated comparison changed")
    if receipt("hook-gap") != [
        [("Reference", 2, 2), ("Tetragon", matched, 2)] for matched in (0, 0, 2, 2)
    ]:
        raise ValueError("Gate C.2 diagnostic comparison changed")
    if receipt("direct-delegated-b") != [[("Primary effects", 4, 4)]]:
        raise ValueError("Gate B synthetic comparison changed")
    if receipt("direct-delegated-c") != [
        [("Direct primary effects", 0, 8), ("Delegated primary effects", 8, 8)]
    ]:
        raise ValueError("Gate C primary comparison changed")
    classes = {key: item["provenance"] for key, item in findings.items()}
    if classes != {"delegated-effect-v-cause": "measured", "hook-gap": "measured",
                   "direct-delegated-b": "synthetic", "direct-delegated-c": "measured"}:
        raise ValueError("Pilot evidence labels changed")
    minima = {item["id"]: item["minima"] for item in findings.values() if "minima" in item}
    # Pin the approved lens sets, path and claim names, and cutoff qualifications.
    if sha256(json.dumps(minima, sort_keys=True).encode()).hexdigest() != (
        "4ae7ab1632b7bc97286b51da3784fda2062833eacbd4ffd8f2b5a8f01061594f"
    ):
        raise ValueError("Pilot study minima changed")
    if "Gate C.3 remains synthetic" not in profile["scope"]:
        raise ValueError("Gate C.3 synthetic scope missing")


def validate_profile(profile, schema, graph=None):
    Draft202012Validator(schema).validate(profile)
    serialized = json.dumps(profile, ensure_ascii=False).lower()
    if "file://" in serialized or "<script" in serialized:
        raise ValueError("Private reference or executable content in public profile")

    references = named(profile["references"], "reference")
    for item in references.values():
        if not public_reference(item["url"]):
            raise ValueError("References must be public HTTPS URLs without credentials")
    sources = named(profile["collectionSources"], "collection source")
    families = named(profile["observationFamilies"], "observation family")
    variations = named(profile["variations"], "variation")
    named(profile.get("placements", []), "placement")
    if "initialVariation" in profile:
        compatible([profile["initialVariation"]], variations, "initial variation")
    if "initialObservation" in profile:
        compatible([profile["initialObservation"]], families, "initial observation")
    for family in families.values():
        compatible(family.get("collectionAny", []), sources, "collection source")
    for preset in named(profile["presets"], "preset").values():
        compatible(preset["sources"], sources, "preset source")

    if graph is not None and profile["behavioralGraph"]["baseline"] != graph["baseline"]["siteCommit"]:
        raise ValueError("Profile and behavioral graph baselines differ")
    objectives = named(graph["objectives"], "objective") if graph is not None else {}
    for variation in variations.values():
        compatible(variation["refs"], references, "reference")
        cells = [row["family"] for row in variation["observations"]]
        if len(cells) != len(set(cells)):
            raise ValueError("Duplicate observation for a variation and family")
        compatible(cells, families, "observation family")
        for claim in variation["claims"]:
            compatible([id for group in claim["requiresAny"] for id in group], sources, "claim source")
        if relation := variation.get("graph"):
            compatible([relation["objective"]], objectives, "graph objective")
            routes = named(objectives[relation["objective"]]["routes"], "route")
            compatible([relation["route"]], routes, "graph route")

    for item in named(profile.get("evidenceExamples", []), "evidence example").values():
        compatible(item["refs"], references, "evidence reference")
    for item in named(profile.get("findings", []), "finding").values():
        compatible(item["refs"], references, "study reference")
        for row in item.get("comparisons", []):
            labels = set()
            for metric in row["metrics"]:
                if metric["label"] in labels:
                    raise ValueError("Duplicate metric claim in one comparison")
                labels.add(metric["label"])
                if metric["confirmed"] > metric["denominator"]:
                    raise ValueError("Confirmed count exceeds eligible denominator")
    if profile["id"] == PILOT:
        exact_pilot_counts(profile)


def validate_catalog(root):
    schema = json_file(root / "schema/catalog-research-profile.v1.schema.json")
    canon = {path.stem for path in (root / "chokepoints").rglob("*.yml")}
    pages = {}
    for source in (root / "catalog-profiles").glob("*.md"):
        match = re.fullmatch(r"---\n(.*?)\n---\n(.*)", source.read_text(encoding="utf-8"), re.S)
        if match is None:
            raise ValueError(f"Missing front matter in {source.name}")
        metadata = yaml.safe_load(match[1])
        Draft202012Validator(schema).validate(metadata)
        slug = metadata["permalink"].strip("/").split("/")[-1]
        if slug in canon or slug in pages:
            raise ValueError("Research profile collides with a catalog slug")
        for relation in metadata["related_entries"]:
            if relation["slug"] not in canon:
                raise ValueError("Unknown related canon entry")
        for section in ("attack-chokepoints", "variations", "detection-strategy", "prevention"):
            if match[2].count(f'id="{section}"') != 1:
                raise ValueError(f"Missing or duplicate catalog section {section}")
        pages[slug] = metadata
    return canon, pages


def validate_index(root):
    schema = json_file(root / "schema/defensive-coverage.v1.schema.json")
    canon, catalog = validate_catalog(root)
    index_path = root / "_data/defensive_coverage_profiles.yml"
    index = yaml.safe_load(index_path.read_text(encoding="utf-8")) or {}
    seen = set()
    for slug, entry in index.items():
        if slug not in canon and slug not in catalog:
            raise ValueError(f"Unknown profile index slug {slug}")
        if not isinstance(entry, dict) or entry.keys() - {"profile", "research", "explorer", "telemetry_value", "sigma_bundle"}:
            raise ValueError(f"Invalid profile index entry {slug}")
        path = entry.get("profile", "")
        if not DATA_PATH.fullmatch(path) or not path.startswith("/assets/data/defensive-coverage/"):
            raise ValueError(f"Invalid defensive coverage asset for {slug}")
        if path in seen:
            raise ValueError("One profile asset is indexed twice")
        seen.add(path)
        for key in ("research", "explorer"):
            route = entry.get(key)
            if route and (not SITE_PATH.fullmatch(route) or not (root / route.lstrip("/")).is_dir()):
                raise ValueError(f"Unknown {key} route for {slug}")
        profile = json_file(root / path.lstrip("/"))
        graph = None
        if info := profile.get("behavioralGraph"):
            if not DATA_PATH.fullmatch(info["path"]) or entry.get("explorer") != info["explorer"]:
                raise ValueError(f"Invalid graph or Explorer link for {slug}")
            graph_path = root / info["path"].lstrip("/")
            if slug == PILOT and sha256(graph_path.read_bytes()).hexdigest() != PILOT_GRAPH_SHA256:
                raise ValueError("Approved container graph bytes changed")
            graph = json_file(graph_path)
        if profile.get("id") != slug:
            raise ValueError(f"Profile ID does not match indexed slug {slug}")
        validate_profile(profile, schema, graph)
    return len(index)


if __name__ == "__main__":
    try:
        count = validate_index(ROOT)
        print(f"Validated {count} defensive coverage profile(s).")
    except (ValidationError, ValueError, KeyError, TypeError, OSError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)

