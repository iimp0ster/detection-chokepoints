from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from check_chokepoint_regression import (  # noqa: E402
    RegressionError,
    load_receipt,
    sha256_file,
    validate_contract,
    validate_contract_data,
    validate_receipt_data,
    validate_rendered_page,
)


SLUG = "trusted-binary-dll-sideloading"
RECEIPT = REPO / "tests" / "fixtures" / f"{SLUG}-validation.json"


class TrustedBinaryDllSideloadingRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data, cls.hashes = validate_contract(REPO, SLUG)
        cls.receipt = load_receipt(RECEIPT)

    def test_current_chokepoint_contract(self) -> None:
        self.assertEqual(len(self.data["Variations"]), 4)
        self.assertEqual(len(self.data["OsintSources"]), 4)
        self.assertEqual(set(self.hashes), {"research.yml", "hunt.yml", "analyst.yml"})

    def test_validation_receipt_covers_current_rules(self) -> None:
        validate_receipt_data(self.data, self.hashes, self.receipt)
        self.assertEqual(len(self.receipt["cases"]), 6)
        self.assertEqual(sum(len(case["tiers"]) for case in self.receipt["cases"]), 18)

    def test_single_variation_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.data)
        mutated["Variations"] = mutated["Variations"][:1]
        with self.assertRaisesRegex(RegressionError, "at least two variations"):
            validate_contract_data(mutated, REPO)

    def test_unknown_placeholder_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.data)
        mutated["Chokepoints"][0]["WhyCantBypass"] = "<UNKNOWN -- needs evidence>"
        with self.assertRaisesRegex(RegressionError, "unknown placeholders"):
            validate_contract_data(mutated, REPO)

    def test_duplicate_source_evidence_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.data)
        for variation in mutated["Variations"]:
            variation["SourceURL"] = "https://example.test/one-report"
        with self.assertRaisesRegex(RegressionError, "at least two source URLs"):
            validate_contract_data(mutated, REPO)

    def test_stale_sigma_hash_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.receipt)
        mutated["tiers"][0]["sigma_sha256"] = "0" * 64
        with self.assertRaisesRegex(RegressionError, "current Sigma hashes"):
            validate_receipt_data(self.data, self.hashes, mutated)

    def test_sigma_hash_ignores_checkout_line_endings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lf = Path(directory) / "lf.yml"
            crlf = Path(directory) / "crlf.yml"
            changed = Path(directory) / "changed.yml"
            content = "title: test\ndetection:\n  condition: selection\n"
            lf.write_bytes(content.encode("utf-8"))
            crlf.write_bytes(content.replace("\n", "\r\n").encode("utf-8"))
            changed.write_bytes(content.replace("selection", "changed").encode("utf-8"))
            self.assertEqual(sha256_file(lf), sha256_file(crlf))
            self.assertNotEqual(sha256_file(lf), sha256_file(changed))

    def test_changed_tier_outcome_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.receipt)
        mutated["cases"][0]["tiers"][0]["actual"] = True
        with self.assertRaisesRegex(RegressionError, "changed outcome"):
            validate_receipt_data(self.data, self.hashes, mutated)

    def test_missing_case_tier_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.receipt)
        mutated["cases"][0]["tiers"].pop()
        with self.assertRaisesRegex(RegressionError, "does not cover every tier"):
            validate_receipt_data(self.data, self.hashes, mutated)

    def test_built_site_renders_variations_tiers_and_osint(self) -> None:
        page = validate_rendered_page(REPO, SLUG, self.data)
        self.assertTrue(page.is_file())


if __name__ == "__main__":
    unittest.main()
