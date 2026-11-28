import copy
import json
import re
from pathlib import Path
import unittest

from jsonschema import ValidationError

from scripts.validate_defensive_coverage import validate_index, validate_profile

ROOT = Path(__file__).resolve().parents[1]
BASE = "/detection-chokepoints"


def load(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


class DefensiveCoverageTests(unittest.TestCase):
    def setUp(self):
        self.profile = load("assets/data/defensive-coverage/container-escape-variations.v1.json")
        self.schema = load("schema/defensive-coverage.v1.schema.json")
        self.graph = load("assets/data/container-escape-research.v1.json")

    def test_only_pilot_is_indexed(self):
        self.assertEqual(validate_index(ROOT), 1)

    def test_source_only_profile(self):
        profile = copy.deepcopy(self.profile)
        profile["id"] = "example-entry"
        for key in ("behavioralGraph", "evidenceExamples", "findings", "placements"):
            profile.pop(key)
        profile["variations"] = [
            {key: value for key, value in item.items() if key != "graph"}
            for item in profile["variations"]
            if all(obs["state"] in {"source", "context", "hypothesis"} for obs in item["observations"])
        ]
        validate_profile(profile, self.schema)

    def test_unknown_family(self):
        self.profile["variations"][0]["observations"][0]["family"] = "unknown"
        with self.assertRaisesRegex(ValueError, "Unknown observation family"):
            validate_profile(self.profile, self.schema, self.graph)

    def test_unknown_graph_route(self):
        self.profile["variations"][0]["graph"]["route"] = "unlisted"
        with self.assertRaisesRegex(ValueError, "Unknown graph route"):
            validate_profile(self.profile, self.schema, self.graph)

    def test_duplicate_id(self):
        self.profile["observationFamilies"].append(self.profile["observationFamilies"][0])
        with self.assertRaisesRegex(ValueError, "Duplicate observation family ID"):
            validate_profile(self.profile, self.schema, self.graph)

    def test_unavailable_claim_must_be_explicit(self):
        claim = self.profile["variations"][0]["claims"][0]
        claim["requiresAny"] = []
        with self.assertRaises(ValidationError):
            validate_profile(self.profile, self.schema, self.graph)

    def test_invalid_counts_and_changed_pilot_measurement(self):
        metric = self.profile["findings"][0]["comparisons"][0]["metrics"][0]
        metric["denominator"] = 0
        with self.assertRaises(ValidationError):
            validate_profile(self.profile, self.schema, self.graph)
        metric["denominator"] = 9
        metric["confirmed"] = 10
        with self.assertRaisesRegex(ValueError, "exceeds eligible denominator"):
            validate_profile(self.profile, self.schema, self.graph)
        metric["confirmed"] = 8
        with self.assertRaisesRegex(ValueError, "delegated comparison changed"):
            validate_profile(self.profile, self.schema, self.graph)

    def test_approved_minima_and_graph_baseline(self):
        self.profile["behavioralGraph"]["baseline"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "baselines differ"):
            validate_profile(self.profile, self.schema, self.graph)
        self.profile["behavioralGraph"]["baseline"] = self.graph["baseline"]["siteCommit"]
        self.profile["findings"][0]["minima"][1]["lenses"].remove("A")
        with self.assertRaisesRegex(ValueError, "study minima changed"):
            validate_profile(self.profile, self.schema, self.graph)

    def test_built_site_nests_only_pilot_inside_detection(self):
        build = ROOT / "_site"
        if not (build / "index.html").is_file():
            self.skipTest("Requires a Jekyll build")
        catalog = build / "chokepoints"
        pilot = catalog / "container-escape-variations/index.html"
        rendered = pilot.read_text(encoding="utf-8")
        self.assertEqual(rendered.count('id="defensive-coverage"'), 1)
        detection = re.search(r'<section [^>]*id="detection-strategy"[^>]*>.*?</section>', rendered, re.S)
        self.assertIsNotNone(detection)
        self.assertIn('id="defensive-coverage"', detection[0])
        self.assertIn('id="tv-relevance"', detection[0])
        self.assertIn('id="tv-goal"', detection[0])
        self.assertIn('defensive-coverage-value.mjs', detection[0])
        navigation = re.search(r'<nav [^>]*id="chokepoint-nav"[^>]*>(.*?)</nav>', rendered, re.S)
        self.assertIsNotNone(navigation)
        self.assertEqual(re.findall(r'<a href="#([^"]+)"[^>]*>([^<]+)</a>', navigation[1]), [
            ("overview", "Overview"), ("attack-chokepoints", "Chokepoints"),
            ("variations", "Variations"), ("detection-strategy", "Detection"),
            ("prevention", "Prevention"), ("related", "Related"),
        ])
        for anchor in ("boundaries", "candidates", "detection", "controls", "limits",
                       "variations", "defensive-coverage"):
            self.assertEqual(rendered.count(f'id="{anchor}"'), 1, anchor)
        self.assertNotIn("Compare review layouts", rendered)
        self.assertIn(BASE + "/lens-explorer/container-escape/", rendered)
        self.assertIn(BASE + "/research/container-escape/", rendered)
        for page in catalog.glob("*/index.html"):
            if page != pilot:
                other = page.read_text(encoding="utf-8")
                self.assertNotIn("defensive-coverage.mjs", other, str(page))
                self.assertNotIn("defensive-coverage-value.mjs", other, str(page))
        for page in ("assets/js/defensive-coverage.mjs",
                     "assets/data/container-escape-research.v1.json",
                     "lens-explorer/container-escape/index.html",
                     "research/container-escape/index.html"):
            self.assertTrue((build / page).is_file(), page)

