
import unittest

from modules.safety_manager import (
    check_authorization,
    validate_operation,
    get_safety_notice
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
        self.assertFalse(
            result["automatic_remediation"]
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
