
import unittest

from modules.drift_detector import compare_configurations


class TestDriftDetector(unittest.TestCase):

    def test_no_configuration_change(self):
        """Test when all configurations remain unchanged."""

        baseline = {
            "firewall": True,
            "defender": True,
            "smb1": False
        }

        current = {
            "firewall": True,
            "defender": True,
            "smb1": False
        }

        results = compare_configurations(baseline, current)

        self.assertEqual(len(results), 3)

        for result in results:
            self.assertEqual(result["status"], "NO CHANGE")

    def test_firewall_change_detected(self):
        """Test when firewall configuration changes."""

        baseline = {
            "firewall": True,
            "defender": True,
            "smb1": False
        }

        current = {
            "firewall": False,
            "defender": True,
            "smb1": False
        }

        results = compare_configurations(baseline, current)

        firewall_result = next(
            result for result in results
            if result["control"] == "firewall"
        )

        self.assertEqual(
            firewall_result["status"],
            "DRIFT DETECTED"
        )

    def test_smb1_change_detected(self):
        """Test when SMB1 configuration changes."""

        baseline = {
            "firewall": True,
            "defender": True,
            "smb1": False
        }

        current = {
            "firewall": True,
            "defender": True,
            "smb1": True
        }

        results = compare_configurations(baseline, current)

        smb_result = next(
            result for result in results
            if result["control"] == "smb1"
        )

        self.assertEqual(
            smb_result["status"],
            "DRIFT DETECTED"
        )

    def test_missing_control_detected(self):
        """Test when a baseline control is missing."""

        baseline = {
            "firewall": True,
            "defender": True,
            "smb1": False
        }

        current = {
            "defender": True,
            "smb1": False
        }

        results = compare_configurations(baseline, current)

        firewall_result = next(
            result for result in results
            if result["control"] == "firewall"
        )

        self.assertEqual(
            firewall_result["status"],
            "MISSING CONTROL"
        )

    def test_new_control_detected(self):
        """Test when a new control appears."""

        baseline = {
            "firewall": True,
            "smb1": False
        }

        current = {
            "firewall": True,
            "smb1": False,
            "defender": True
        }

        results = compare_configurations(baseline, current)

        defender_result = next(
            result for result in results
            if result["control"] == "defender"
        )

        self.assertEqual(
            defender_result["status"],
            "NEW CONTROL"
        )

    def test_invalid_baseline_rejected(self):
        """Test that an invalid baseline is rejected."""

        with self.assertRaises(ValueError):
            compare_configurations(
                None,
                {"firewall": True}
            )

    def test_invalid_current_configuration_rejected(self):
        """Test that invalid current configuration is rejected."""

        with self.assertRaises(ValueError):
            compare_configurations(
                {"firewall": True},
                None
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
