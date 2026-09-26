import unittest
import re
from pathlib import Path

import yaml


ROOT = Path(__file__).parents[1]
RULES = ROOT / "sigma-rules" / "disabling-native-tools"


def load_rule(tier):
    return yaml.safe_load((RULES / f"{tier}.yml").read_text(encoding="utf-8"))


def selection_matches(selection, image, command_line):
    for key, expected in selection.items():
        values = expected if isinstance(expected, list) else [expected]
        field, *modifiers = key.split("|")
        observed = image if field == "Image" else command_line
        if "endswith" in modifiers and not any(observed.lower().endswith(value.lower()) for value in values):
            return False
        if "contains" in modifiers:
            checks = [value.lower() in observed.lower() for value in values]
            if ("all" in modifiers and not all(checks)) or ("all" not in modifiers and not any(checks)):
                return False
        if "re" in modifiers and not any(re.search(value, observed) for value in values):
            return False
    return True


def hunt_matches(image, command_line):
    detection = load_rule("hunt")["detection"]
    return all(selection_matches(detection[name], image, command_line) for name in (
        "selection_binary", "selection_path", "selection_value", "selection_write", "selection_enabled"
    ))


class DisableRegistryToolsRuleTests(unittest.TestCase):
    def test_atomic_positive_matches(self):
        command = (
            r"reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System "
            r"/v DisableRegistryTools /t REG_DWORD /d 1 /f"
        )
        self.assertTrue(hunt_matches(r"C:\Windows\System32\reg.exe", command))

    def test_unrelated_dword_write_stays_quiet(self):
        command = r"reg add HKCU\Software\Example /v Enabled /t REG_DWORD /d 1 /f"
        self.assertFalse(hunt_matches(r"C:\Windows\System32\reg.exe", command))

    def test_policy_disable_value_stays_quiet(self):
        command = (
            r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System "
            r"/v DisableRegistryTools /t REG_DWORD /d 0 /f"
        )
        self.assertFalse(hunt_matches(r"C:\Windows\System32\reg.exe", command))

    def test_multi_digit_value_does_not_satisfy_enabled_value(self):
        command = (
            r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System "
            r"/v DisableRegistryTools /t REG_DWORD /d 10 /f"
        )
        self.assertFalse(hunt_matches(r"C:\Windows\System32\reg.exe", command))

    def test_non_reg_binary_stays_quiet(self):
        command = (
            r"tool add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System "
            r"/v DisableRegistryTools /t REG_DWORD /d 1 /f"
        )
        self.assertFalse(hunt_matches(r"C:\Tools\tool.exe", command))


if __name__ == "__main__":
    unittest.main()
