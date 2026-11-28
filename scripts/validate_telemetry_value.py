"""Validate indexed telemetry-value sidecars against their evidence and route scope."""
from hashlib import sha256

from jsonschema import Draft202012Validator
import yaml

from validate_defensive_coverage import ROOT, PILOT, compatible, json_file, named, public_reference

FROZEN_SHA256 = "7cb327d92f11213863515aea0340cb69616a49aeea0df8ce73dd00ad58699323"


def validate_pilot(root=ROOT):
    index = yaml.safe_load((root / "_data/defensive_coverage_profiles.yml").read_text(encoding="utf-8"))
    entries = {slug: entry for slug, entry in index.items() if "telemetry_value" in entry}
    if set(entries) != {PILOT}:
        raise ValueError("Only the approved pilot can be indexed")
    entry = entries[PILOT]
    expected = f"/assets/data/telemetry-value/{PILOT}.v1.json"
    if entry["telemetry_value"] != expected:
        raise ValueError("Unexpected pilot sidecar path")
    profile = json_file(root / expected.lstrip("/"))
    Draft202012Validator(json_file(root / "schema/telemetry-value.v1.schema.json")).validate(profile)
    if profile["entry"] != PILOT:
        raise ValueError("Sidecar entry differs from its catalog scope")

    graph_info = json_file(root / entry["profile"].lstrip("/"))["behavioralGraph"]
    objectives = named(json_file(root / graph_info["path"].lstrip("/"))["objectives"], "objective")
    refs = named(profile["references"], "reference")
    caps = named(profile["capabilities"], "capability")
    variants = named(profile["variations"], "variation")
    for ref in refs.values():
        if not public_reference(ref["url"]):
            raise ValueError("Reference must be public and contain no credentials")
    compatible([profile["defaultVariation"]], variants, "default variation")
    selection = profile["studySelection"]
    for item in variants.values():
        active = {id: caps[id] for id in item["capabilities"]}
        compatible(item["baseline"], active, "baseline capability")
        compatible(item["refs"], refs, "variation reference")
        for claim in named(item["claims"], "claim").values():
            compatible([id for group in claim["requiresAny"] for id in group], active, "claim capability")
            compatible([id for pair in claim["distinctOrigins"] for id in pair], active, "independent capability")
        if exercise := item.get("explorer"):
            routes = named(objectives[exercise["objective"]]["routes"], "route")
            compatible([exercise["route"]], routes, "exercise route")
        if "study" in item and (item["study"] != selection["id"] or item["maturity"] != "measured"):
            raise ValueError("Study does not match measured variation")
    validate_matrix(profile["relevanceMatrix"], variants, caps, refs)
    dataset_path = root / "assets/data/detection-lens-explorer.v1.json"
    frozen = sha256(dataset_path.read_bytes()).hexdigest()
    if frozen != FROZEN_SHA256 or selection["approvedSha256"] != FROZEN_SHA256:
        raise ValueError("Approved dataset hash changed")
    if (selection["study"], selection["revision"], selection["profile"], selection["cohort"], selection["arm"]) != (
        "gate-c2", "f0c5aaf17d51a60007d8f596239cd317b99507a1", "augmented", "path/workload_delegated", None
    ):
        raise ValueError("Approved replay scope changed")
    if set(selection["metrics"]) != {"effect", "causal", "authorization", "boundary"}:
        raise ValueError("Approved replay claims changed")
    print("Validated one telemetry-value pilot, its matrix, and frozen study selection.")


def validate_matrix(matrix, variants, caps, refs):
    rows = named(matrix["rows"], "matrix row")
    columns = [col["variation"] for col in matrix["columns"]]
    if len(columns) != len(set(columns)) or set(columns) != variants.keys():
        raise ValueError("Matrix columns must cover each variation once")
    compatible([matrix["defaultRow"]], rows, "default matrix row")
    seen_comparison = False
    for column in matrix["columns"]:
        variant = column["variation"]
        expected = {"diagnostic": "diagnostic", "synthetic-direct": "synthetic"}.get(variant, "tradecraft")
        if column.get("kind", "tradecraft") != expected or (expected == "tradecraft" and seen_comparison):
            raise ValueError("Comparison cases must be labeled and grouped after the tradecraft")
        seen_comparison |= expected != "tradecraft"
    seen = set()
    for cell in matrix["cells"]:
        key = (cell["row"], cell["variation"])
        if key in seen:
            raise ValueError("Each matrix cell must have a unique coordinate")
        seen.add(key)
        compatible([cell["row"]], rows, "cell row")
        compatible(cell["capabilities"], caps, "cell capability")
        compatible(cell["refs"], refs, "cell reference")
        item = variants[cell["variation"]]
        claims = named(item["claims"], "claim")
        compatible(cell["claims"], claims, "cell claim")
        if cell["basis"] in {"measured", "synthetic"} and cell["basis"] != item["maturity"]:
            raise ValueError("Cell evidence basis conflicts with the variation")
        if cell["role"] in {"primary", "complementary"}:
            required = {id: caps[id] for claim_id in cell["claims"]
                        for group in claims[claim_id]["requiresAny"] for id in group}
            compatible(cell["capabilities"], required, "claim-linked capability")


if __name__ == "__main__":
    validate_pilot()

