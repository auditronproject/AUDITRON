
import unittest
from unittest.mock import patch

from modules.cis_checker import run_cis_audit


class TestCISChecker(unittest.TestCase):

    def run_mock_audit(
        self,
        firewall_enabled=True,
        defender_enabled=True,
        smb1_enabled=False,
        antivirus_data=None,
        firewall_data=None,
        defender_data=None,
        smb1_data=None,
        guest_data=None,
        uac_data=None
    ):

        if firewall_data is None:
            firewall_data = [
                {"Name": "Domain", "Enabled": firewall_enabled},
                {"Name": "Private", "Enabled": firewall_enabled},
                {"Name": "Public", "Enabled": firewall_enabled}
            ]

        if defender_data is None:
            defender_data = {
                "AMServiceEnabled": defender_enabled,
                "AntivirusEnabled": defender_enabled,
                "RealTimeProtectionEnabled": defender_enabled
            }

        if smb1_data is None:
            smb1_data = {
                "EnableSMB1Protocol": smb1_enabled
            }

        if guest_data is None:
            guest_data = {"Enabled": False}

        if uac_data is None:
            uac_data = {"EnableLUA": 1}

        if antivirus_data is None:
            antivirus_data = [
                {
                    "displayName": "McAfee",
                    "productState": 397568
                }
            ]

        with patch(
            "modules.cis_checker.collect_firewall_status",
            return_value=firewall_data
        ), patch(
            "modules.cis_checker.collect_defender_status",
            return_value=defender_data
        ), patch(
            "modules.cis_checker.collect_smb1_status",
            return_value=smb1_data
        ), patch(
            "modules.cis_checker.collect_antivirus_providers",
            return_value=antivirus_data
        ), patch(
            "modules.cis_checker.collect_guest_account_status",
            return_value=guest_data
        ), patch(
            "modules.cis_checker.collect_uac_status",
            return_value=uac_data
        ):

            return run_cis_audit()

    def get_status(self, results):
        return {
            item["control"]: item["status"]
            for item in results
        }

    # ======================================
    # NORMAL CONFIGURATION TESTS
    # ======================================

    def test_secure_configuration(self):

        results = self.run_mock_audit()
        status = self.get_status(results)

        self.assertEqual(status["Windows Firewall"], "PASS")
        self.assertEqual(status["Microsoft Defender"], "PASS")
        self.assertEqual(status["SMBv1"], "PASS")
        self.assertEqual(status["Third-Party Antivirus"], "INFO")

    def test_firewall_disabled(self):

        results = self.run_mock_audit(
            firewall_enabled=False
        )

        status = self.get_status(results)

        self.assertEqual(status["Windows Firewall"], "FAIL")

    def test_defender_disabled_with_third_party_antivirus(self):

        results = self.run_mock_audit(
            defender_enabled=False
        )

        status = self.get_status(results)

        self.assertEqual(status["Microsoft Defender"], "INFO")

    def test_defender_disabled_without_third_party_antivirus(self):

        results = self.run_mock_audit(
            defender_enabled=False,
            antivirus_data=[
                {
                    "displayName": "Windows Defender",
                    "productState": 397568
                }
            ]
        )

        status = self.get_status(results)

        self.assertEqual(status["Microsoft Defender"], "FAIL")

    def test_smb1_enabled(self):

        results = self.run_mock_audit(
            smb1_enabled=True
        )

        status = self.get_status(results)

        self.assertEqual(status["SMBv1"], "FAIL")

    def test_third_party_antivirus_detected(self):

        results = self.run_mock_audit()

        status = self.get_status(results)

        self.assertEqual(status["Third-Party Antivirus"], "INFO")

    # ======================================
    # FIREWALL EDGE CASE TESTS
    # ======================================

    def test_firewall_unknown_status(self):

        results = self.run_mock_audit(
            firewall_data=[
                {"Name": "Domain", "Enabled": None},
                {"Name": "Private", "Enabled": True}
            ]
        )

        status = self.get_status(results)

        self.assertEqual(status["Windows Firewall"], "WARNING")

    def test_firewall_no_valid_data(self):

        results = self.run_mock_audit(
            firewall_data=[]
        )

        status = self.get_status(results)

        self.assertEqual(status["Windows Firewall"], "ERROR")

    def test_firewall_disabled_and_unknown_profile(self):

        results = self.run_mock_audit(
            firewall_data=[
                {"Name": "Domain", "Enabled": False},
                {"Name": "Private", "Enabled": None}
            ]
        )

        status = self.get_status(results)

        self.assertEqual(status["Windows Firewall"], "FAIL")

    # ======================================
    # DEFENDER EDGE CASE TESTS
    # ======================================

    def test_defender_missing_property(self):

        results = self.run_mock_audit(
            defender_data={
                "AMServiceEnabled": True,
                "AntivirusEnabled": True
            }
        )

        status = self.get_status(results)

        self.assertEqual(status["Microsoft Defender"], "WARNING")

    def test_defender_rejects_integer_boolean_values(self):

        results = self.run_mock_audit(
            defender_data={
                "AMServiceEnabled": 1,
                "AntivirusEnabled": 1,
                "RealTimeProtectionEnabled": 1
            }
        )

        status = self.get_status(results)

        self.assertEqual(status["Microsoft Defender"], "WARNING")

    def test_defender_disabled_when_provider_collection_fails(self):

        with patch(
            "modules.cis_checker.collect_firewall_status",
            return_value=[
                {"Name": "Domain", "Enabled": True}
            ]
        ), patch(
            "modules.cis_checker.collect_defender_status",
            return_value={
                "AMServiceEnabled": False,
                "AntivirusEnabled": False,
                "RealTimeProtectionEnabled": False
            }
        ), patch(
            "modules.cis_checker.collect_smb1_status",
            return_value={
                "EnableSMB1Protocol": False
            }
        ), patch(
            "modules.cis_checker.collect_antivirus_providers",
            side_effect=RuntimeError("Provider collection failed")
        ), patch(
            "modules.cis_checker.collect_guest_account_status",
            return_value={"Enabled": False}
        ), patch(
            "modules.cis_checker.collect_uac_status",
            return_value={"EnableLUA": 1}
        ):

            results = run_cis_audit()

        status = self.get_status(results)

        self.assertEqual(status["Microsoft Defender"], "WARNING")
        self.assertEqual(status["Third-Party Antivirus"], "ERROR")

    # ======================================
    # ANTIVIRUS EDGE CASE TESTS
    # ======================================

    def test_no_antivirus_provider_returned(self):

        results = self.run_mock_audit(
            antivirus_data=[]
        )

        status = self.get_status(results)

        self.assertEqual(status["Third-Party Antivirus"], "WARNING")

    def test_invalid_antivirus_provider_data(self):

        results = self.run_mock_audit(
            antivirus_data="invalid provider data"
        )

        status = self.get_status(results)

        self.assertEqual(status["Third-Party Antivirus"], "ERROR")

    # ======================================
    # SMBv1 EDGE CASE TESTS
    # ======================================

    def test_smb1_unknown_status(self):

        results = self.run_mock_audit(
            smb1_data={
                "EnableSMB1Protocol": None
            }
        )

        status = self.get_status(results)

        self.assertEqual(status["SMBv1"], "WARNING")

    def test_smb1_rejects_integer_boolean_values(self):

        results = self.run_mock_audit(
            smb1_data={
                "EnableSMB1Protocol": 0
            }
        )

        status = self.get_status(results)

        self.assertEqual(status["SMBv1"], "WARNING")

    # ======================================
    # GUEST ACCOUNT TESTS
    # ======================================

    def test_guest_account_statuses(self):

        cases = [
            ({"Enabled": False}, "PASS"),
            ({"Enabled": True}, "FAIL"),
            ({"Enabled": None}, "WARNING"),
            ("invalid", "ERROR")
        ]

        for data, expected in cases:
            with self.subTest(data=data):
                status = self.get_status(
                    self.run_mock_audit(guest_data=data)
                )
                self.assertEqual(status["Guest Account"], expected)

    # ======================================
    # UAC TESTS
    # ======================================

    def test_uac_statuses(self):

        cases = [
            ({"EnableLUA": 1}, "PASS"),
            ({"EnableLUA": 0}, "FAIL"),
            ({"EnableLUA": None}, "WARNING"),
            ({"EnableLUA": True}, "WARNING"),
            ("invalid", "ERROR")
        ]

        for data, expected in cases:
            with self.subTest(data=data):
                status = self.get_status(
                    self.run_mock_audit(uac_data=data)
                )
                self.assertEqual(
                    status["User Account Control"], expected
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
