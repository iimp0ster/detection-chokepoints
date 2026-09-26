import importlib.util
import tempfile
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "check_sigma", Path(__file__).parents[1] / "scripts" / "check_sigma.py"
)
CHECK_SIGMA = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK_SIGMA)


class CheckSigmaTests(unittest.TestCase):
    def test_traceback_reason_reports_the_exception(self):
        output = "Traceback (most recent call last):\n  internal frame\nTypeError: invalid condition"
        self.assertEqual(CHECK_SIGMA.reason(output), "TypeError: invalid condition")

    def test_full_discovery_accepts_both_sigma_extensions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one.yml").write_text("title: one", encoding="utf-8")
            (root / "two.yaml").write_text("title: two", encoding="utf-8")
            (root / "ignore.txt").write_text("not sigma", encoding="utf-8")
            self.assertEqual(
                [path.name for path in CHECK_SIGMA.discover_rules(root)],
                ["one.yml", "two.yaml"],
            )


if __name__ == "__main__":
    unittest.main()
