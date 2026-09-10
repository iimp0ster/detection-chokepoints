from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

import yaml


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from validate_schema import validate_chokepoint_page_standard, validate_entry  # noqa: E402


SCHEDULED_TASK = REPO / "chokepoints" / "persistence" / "scheduled-task-job-scheduled-task.yml"
LAYOUT = REPO / "_layouts" / "chokepoint.html"


class ChokepointPageStandardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = yaml.safe_load(SCHEDULED_TASK.read_text(encoding="utf-8"))
        cls.layout = LAYOUT.read_text(encoding="utf-8")

    def test_scheduled_task_clears_versioned_page_standard(self) -> None:
        self.assertEqual(self.data["PageStandardVersion"], 1)
        self.assertEqual(validate_entry(SCHEDULED_TASK), [])

    def test_standard_rejects_missing_top_level_constant(self) -> None:
        mutated = copy.deepcopy(self.data)
        mutated.pop("TheConstant")
        errors: list[str] = []
        validate_chokepoint_page_standard(errors, "fixture.yml", mutated)
        self.assertTrue(any("requires TheConstant" in error for error in errors))

    def test_standard_accepts_clickfix_payload_material(self) -> None:
        mutated = copy.deepcopy(self.data)
        mutated["Variations"][0].pop("Command")
        mutated["Variations"][0]["Payloads"] = [{"Command": "source-grounded example"}]
        errors: list[str] = []
        validate_chokepoint_page_standard(errors, "fixture.yml", mutated)
        self.assertFalse(any("Variations[1] requires Command or Payloads" in error for error in errors))

    def test_standard_rejects_one_report_repeated_as_two_variations(self) -> None:
        mutated = copy.deepcopy(self.data)
        for variation in mutated["Variations"]:
            variation["SourceURL"] = "https://example.test/one-report"
        errors: list[str] = []
        validate_chokepoint_page_standard(errors, "fixture.yml", mutated)
        self.assertTrue(any("2 independent variation SourceURL" in error for error in errors))

    def test_standard_ignores_query_and_fragment_source_url_noise(self) -> None:
        mutated = copy.deepcopy(self.data)
        source = "https://example.test/report"
        for index, variation in enumerate(mutated["Variations"]):
            variation["SourceURL"] = f"{source}/?copy={index}#page-{index}"
        errors: list[str] = []
        validate_chokepoint_page_standard(errors, "fixture.yml", mutated)
        self.assertTrue(any("2 independent variation SourceURL" in error for error in errors))

    def test_scheduled_task_receipt_is_explicitly_superseded(self) -> None:
        receipt = yaml.safe_load(
            (REPO / "validation-results" / "scheduled-task-job-scheduled-task.json").read_text(encoding="utf-8")
        )
        self.assertEqual(receipt["status"], "superseded")

    def test_standard_rejects_implicit_detection_validation(self) -> None:
        mutated = copy.deepcopy(self.data)
        mutated["Detections"][0].pop("Validation")
        errors: list[str] = []
        validate_chokepoint_page_standard(errors, "fixture.yml", mutated)
        self.assertTrue(any("Research Detection requires explicit Validation metadata" in error for error in errors))

    def test_emulation_disables_every_registered_task(self) -> None:
        script = (REPO / self.data["EmulationScript"]["File"]).read_text(encoding="utf-8")
        self.assertIn("New-ScheduledTaskSettingsSet -Disable", script)
        self.assertIn("-Settings $DisabledSettings", script)
        self.assertIn("if ($Registered.State -ne 'Disabled')", script)
        self.assertIn("Microsoft\\Windows\\ApplicationData\\DsSvcCleanup-$Suffix", script)
        self.assertNotIn('"Windows\\ApplicationData\\DsSvcCleanup-$Suffix"', script)

    def test_cleanup_reuses_the_original_run_suffix(self) -> None:
        script = (REPO / self.data["EmulationScript"]["File"]).read_text(encoding="utf-8")
        self.assertIn("[string]$RunSuffix", script)
        self.assertIn("-CleanupOnly requires the eight-character RunSuffix", script)

    def test_grouped_renderer_preserves_iok_rule_links(self) -> None:
        self.assertIn("det.SigmaRule | default: det.IokRule", self.layout)
        self.assertIn("IOK Rule - {{ det.Level }} Level", self.layout)

    def test_shared_renderer_uses_current_presentation_contract(self) -> None:
        self.assertIn('class="language-yaml"', self.layout)
        self.assertIn("if (window.hljs)", self.layout)
        self.assertIn(">Prevention</h2>", self.layout)
        self.assertNotIn("Prevention &amp; Deception", self.layout)
        self.assertNotIn(">Deception opportunities</h3>", self.layout)
        self.assertNotIn(">References</h2>", self.layout)

    def test_donutloader_procedure_remains_source_literal(self) -> None:
        variation = next(row for row in self.data["Variations"] if "DonutLoader" in row["Name"])
        invocation = variation["Command"]["Invocation"]
        self.assertIn("$vxvI4iCwnpqCjEX", invocation)
        self.assertIn("$BBkphUlrU4QvXFb", invocation)
        self.assertIn("Source-literal", variation["Command"]["Context"])


if __name__ == "__main__":
    unittest.main()
