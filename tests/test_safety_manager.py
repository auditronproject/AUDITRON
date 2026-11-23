
import unittest

from modules.safety_manager import (
    DEFAULT_TARGET_SCOPE,
    check_authorization,
    validate_operation,
    validate_target_scope,
    get_safety_notice,
    get_legal_disclaimer
)


class TestSafetyManager(unittest.TestCase):

    def test_authorized_user_is_allowed(self):
        result = check_authorization(True)
        self.assertTrue(result["allowed"])

    def test_unauthorized_user_is_blocked(self):
        result = check_authorization(False)
        self.assertFalse(result["allowed"])

    def test_read_only_operation_is_allowed(self):
        result = validate_operation("cis_audit")
        self.assertTrue(result["allowed"])

    def test_unapproved_operation_is_blocked(self):
        result = validate_operation("change_firewall")
        self.assertFalse(result["allowed"])

    def test_safety_notice_is_read_only(self):
        result = get_safety_notice()

        self.assertEqual(result["mode"], "READ-ONLY")
        self.assertEqual(result["default_target_scope"], DEFAULT_TARGET_SCOPE)
        self.assertFalse(
            result["automatic_remediation"]
        )
        self.assertTrue(result["kill_switch_enabled"])
        self.assertIn("Computer Crimes Act 1997", result["legal_disclaimer"])

    def test_legal_disclaimer_references_computer_crimes_act(self):
        disclaimer = get_legal_disclaimer()
        self.assertIn("Computer Crimes Act 1997", disclaimer)
        self.assertIn("Act 563", disclaimer)

    def test_default_localhost_scope_is_allowed(self):
        for valid_target in ["127.0.0.1", "localhost", "LOCALHOST", "::1"]:
            result = validate_target_scope(valid_target)
            self.assertTrue(result["allowed"], f"Expected {valid_target} to be allowed")

    def test_external_or_empty_target_scope_is_blocked(self):
        for invalid_target in ["192.168.1.50", "8.8.8.8", "example.com", "", None]:
            result = validate_target_scope(invalid_target)
            self.assertFalse(result["allowed"], f"Expected {invalid_target} to be blocked")


if __name__ == "__main__":
    unittest.main(verbosity=2)
