"""Validate the v1 Lens Explorer projection and its recorded evidence references."""

from itertools import combinations
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "assets/data/detection-lens-explorer.v1.json"
SCHEMA = ROOT / "schema/detection-lens-explorer.v1.schema.json"

CLAIMS = ("capture", "operation", "effect", "attribution", "authorization", "boundary", "causal", "objective")
STATUSES = {"C", "O", "L", "N", "T", "-"}
STUDIES = {"gate-c2": ("Measured", 512), "gate-c3": ("Synthetic", 1024), "gate-c": ("Measured", 192),
           "gate-b": ("Synthetic", 16), "windows": ("Measured", 1), "php": ("Measured", 1)}


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def valid_metric(value):
    return (isinstance(value,list) and len(value)==4
            and all(type(item) is int and item>=0 for item in value[:2])
            and all(item is None or (type(item) is int and item>=0) for item in value[2:])
            and value[0]<=value[1])


def audit(path=DATA):
    raw = path.read_bytes()
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    require(schema["properties"]["schema"]["const"] == "detection-lens-explorer/v1",
            "schema version and validator differ")
    data = json.loads(raw)
    require(data["schema"]=="detection-lens-explorer/v1" and data["claims"]==list(CLAIMS),"invalid schema or claim order")
    require(data["pendingMeasuredStudies"]==["gate-c3"],"C.3 must remain synthetic")
    require({study["id"] for study in data["studies"]}==set(STUDIES),"unexpected study inventory")
    require(len(data["studies"])==len(STUDIES),"duplicated study")
    require(all(re.fullmatch(r"[0-9a-f]{64}", item) for item in data["sourceDigests"].values()),
            "invalid structural source digest")
    for pattern in (rb"https?://", rb"(?i)[a-z]:[/\\]{1,2}users[/\\]", rb"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                    rb"\b[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}\b", rb"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----",
                    rb'"(?:sourceLink|boot_id|proxmoxPassword|expected_verdict|access_token)"'):
        require(not re.search(pattern,raw),f"review dataset has prohibited material {pattern!r}")
    rows=0
    references=0
    for s in data["studies"]:
        evidence_class, expected_rows=STUDIES[s["id"]]
        require(s["evidenceClass"]==evidence_class,"study evidence-class mismatch "+s["id"])
        require(re.fullmatch(r"[0-9a-f]{40}",s["revision"]),"invalid source revision")
        require(s["initialCase"] in s["cases"],"undefined initial case")
        require(all(item["objective"] in data["objectives"] and item["path"] in data["paths"]
                    for item in s["cases"].values()),"undefined graph metadata")
        require(s["lenses"]=="".join(x for x in "PWKDAH" if x in s["lenses"]),"invalid lens order")
        masks={"".join(a) for n in range(len(s["lenses"])+1) for a in combinations(s["lenses"],n)}
        all_points=set()
        local_rows=0
        for g in s["groups"]:
            key=(g["profile"],g["cutoff"],g["arm"])
            require(key not in all_points,"duplicate profile, cutoff or arm")
            all_points.add(key)
            require(set(g["rows"])==masks,"incomplete or invalid powerset")
            local_rows+=len(g["rows"])
            baseline = g["rows"][s["lenses"]][0]
            for stats, refs in g["rows"].values():
                require(set(refs)==set(s["cases"]),"incomplete example roster")
                require(all(type(r) is int and 0<=r<len(s["assessments"]) for r in refs.values()),"missing assessment")
                require(set(stats)==set(baseline)==set(s["cohorts"]),"incomplete cohort roster")
                for cohort, claims in stats.items():
                    require(set(claims)==set(baseline[cohort]),"inconsistent claim inventory")
                    for name,value in claims.items():
                        require(name in s["claims"] and valid_metric(value),"invalid count tuple")
                        require(value[1]==baseline[cohort][name][1],"denominator changes during ablation")
            for cohort, claims in g["minimum"].items():
                for claim, minimum in claims.items():
                    require(claim in s["claims"] or not minimum,"inaccessible nonempty minimum "+s["id"]+"/"+claim)
                    require(set(minimum)<=masks and len(set(map(len,minimum)))<=1
                            and len(set(minimum))==len(minimum),"invalid minimum set")
                    for option in minimum:
                        metric=g["rows"][option][0][cohort][claim]
                        require(metric[1]>0 and metric[0]==metric[1] and metric[3]==0,
                                "recorded minimum lacks its projected positive target or false-confirmation check")
        require(local_rows==expected_rows,"row count changed "+s["id"])
        rows+=local_rows
        for assessment in s["assessments"]:
            require(len(assessment)==len(CLAIMS),"invalid assessment claim count")
            states={item:status for item,(status,_,_) in zip(CLAIMS,assessment)}
            for status, evidence, missing in assessment:
                require(status in STATUSES and set(evidence)<=set(s["evidence"]),"unknown verdict or evidence alias")
                require(all(isinstance(gap,str) for gap in missing),"invalid gap description")
                references+=len(evidence)
            if states["causal"]=="C":
                require(states["effect"]==states["boundary"]=="C","causal confirmation lacks a confirmed endpoint")
    require(rows==1746,"unexpected total replay rows")
    return len(STUDIES), rows, references


if __name__ == "__main__":
    studies, rows, references = audit()
    print(f"Validated {studies} studies, {rows} rows and {references} projected support references.")
