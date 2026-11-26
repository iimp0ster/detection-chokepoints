"""Regression checks for reviewed projections and built Explorer routes."""
from hashlib import sha256
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_lens_explorer", ROOT / "scripts/validate_lens_explorer.py"
)
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class LensExplorerTest(unittest.TestCase):
    def test_reviewed_projection(self):
        self.assertEqual(validator.audit(), (6, 1746, 5371))

    def test_frozen_explorer_dataset(self):
        self.assertEqual(
            sha256(validator.DATA.read_bytes()).hexdigest(),
            "7cb327d92f11213863515aea0340cb69616a49aeea0df8ce73dd00ad58699323",
        )

    def test_projection_rejects_private_reference(self):
        raw = validator.DATA.read_bytes().replace(b'"pendingMeasuredStudies":',
                b'"sourceLink":"https://example.invalid/private","pendingMeasuredStudies":', 1)
        self.assertNotEqual(raw, validator.DATA.read_bytes())
        with TemporaryDirectory() as directory:
            data = Path(directory) / "invalid.json"
            data.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "prohibited material"):
                validator.audit(data)

    def test_site_build_and_base_path(self):
        destination = ROOT / "_site"
        if not destination.exists():
            self.skipTest("Requires a Jekyll build")
        explorer = (destination / "lens-explorer/index.html").read_text(encoding="utf-8")
        research = (destination / "research/index.html").read_text(encoding="utf-8")
        home = (destination / "index.html").read_text(encoding="utf-8")
        self.assertIn('data-dataset="/detection-chokepoints/assets/data/detection-lens-explorer.v1.json"', explorer)
        self.assertIn('src="/detection-chokepoints/assets/js/detection-lens-explorer.mjs"', explorer)
        self.assertIn('href="/detection-chokepoints/assets/css/detection-lens-explorer.css"', explorer)
        self.assertIn('role="tablist"', explorer)
        for control in ("free-explore", "walk-back", "walk-next", "walk-replay", "walk-skip"):
            self.assertIn(f'id="{control}"', explorer)
        for region in ("walk-map", "walk-proof", "walk-findings", "lens-lab"):
            self.assertIn(f'id="{region}"', explorer)
        self.assertIn('<dialog id="lens-presentation"', explorer)
        self.assertIn('href="/detection-chokepoints/lens-explorer/"', research)
        self.assertIn("<table>", research)
        self.assertIn('href="/detection-chokepoints/lens-explorer/"', home)
        self.assertNotIn("detection-lens-explorer.css", home)
        for asset in ("css/style.css", "css/theme-arcade.css", "data/detection-lens-explorer.v1.json"):
            expected = (ROOT / f"assets/{asset}").read_bytes()
            built = (destination / f"assets/{asset}").read_bytes()
            self.assertEqual(sha256(built).digest(), sha256(expected).digest())
