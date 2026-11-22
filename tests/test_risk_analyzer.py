
import unittest

from modules.risk_analyzer import (
    analyze_risks,
    get_risk_summary,
    get_risk_methodology
)


class TestRiskAnalyzer(unittest.TestCase):

    def setUp(self):

        self.audit_results = [
            {
                "control": "Windows Firewall",
                "status": "PASS",
                "details": "All firewall profiles are enabled."
            },
            {
                "control": "Microsoft Defender",
                "status": "FAIL",
                "details": "Real-time protection is disabled."
            },
            {
                "control": "Third-Party Antivirus",
                "status": "INFO",
                "details": "McAfee antivirus provider detected."
            },
            {
                "control": "SMBv1",
                "status": "PASS",
                "details": "SMBv1 is disabled."
            }
        ]

    # ======================================
    # RISK CLASSIFICATION TESTS
    # ======================================

    def test_fail_is_high_risk(self):

        results = analyze_risks(self.audit_results)

        defender = next(
            item for item in results
            if item["control"] == "Microsoft Defender"
        )

        self.assertEqual(defender["risk_level"], "HIGH")
        self.assertEqual(defender["risk_score"], 9)

    def test_pass_is_low_risk(self):

        results = analyze_risks(self.audit_results)

        firewall = next(
            item for item in results
            if item["control"] == "Windows Firewall"
        )

        self.assertEqual(firewall["risk_level"], "LOW")
        self.assertEqual(firewall["risk_score"], 1)

    def test_info_is_informational(self):

        results = analyze_risks(self.audit_results)

        antivirus = next(
            item for item in results
            if item["control"] == "Third-Party Antivirus"
        )

        self.assertEqual(
            antivirus["risk_level"],
            "INFORMATIONAL"
        )

        self.assertEqual(antivirus["risk_score"], 2)

    def test_warning_is_medium_risk(self):

        results = analyze_risks([
            {
                "control": "Windows Firewall",
                "status": "WARNING",
                "details": "Profile status is unknown."
            }
        ])

        self.assertEqual(results[0]["risk_level"], "MEDIUM")
        self.assertEqual(results[0]["risk_score"], 6)

    def test_error_is_undetermined(self):

        results = analyze_risks([
            {
                "control": "Windows Firewall",
                "status": "ERROR",
                "details": "Collection failed."
            }
        ])

        self.assertEqual(
            results[0]["risk_level"],
            "UNDETERMINED"
        )

        self.assertIsNone(results[0]["risk_score"])

    def test_unknown_status_is_undetermined(self):

        results = analyze_risks([
            {
                "control": "Unknown Control",
                "status": "UNKNOWN",
                "details": "Unsupported status."
            }
        ])

        self.assertEqual(
            results[0]["status"],
            "ERROR"
        )

        self.assertEqual(
            results[0]["risk_level"],
            "UNDETERMINED"
        )

    # ======================================
    # FINDING INFORMATION TESTS
    # ======================================

    def test_finding_ids_are_generated(self):

        results = analyze_risks(self.audit_results)

        self.assertEqual(results[0]["finding_id"], "AUD-001")
        self.assertEqual(results[1]["finding_id"], "AUD-002")
        self.assertEqual(results[2]["finding_id"], "AUD-003")
        self.assertEqual(results[3]["finding_id"], "AUD-004")

    def test_risk_explanation_is_generated(self):

        results = analyze_risks(self.audit_results)

        for result in results:
            self.assertTrue(result["risk_explanation"])

    def test_recommendation_is_generated(self):

        results = analyze_risks(self.audit_results)

        for result in results:
            self.assertTrue(result["recommendation"])

    def test_smb1_failure_has_specific_recommendation(self):

        results = analyze_risks([
            {
                "control": "SMBv1",
                "status": "FAIL",
                "details": "SMBv1 is enabled."
            }
        ])

        recommendation = results[0]["recommendation"]

        self.assertIn("Disable SMBv1", recommendation)

    def test_original_details_are_preserved(self):

        results = analyze_risks(self.audit_results)

        self.assertEqual(
            results[1]["details"],
            "Real-time protection is disabled."
        )

    # ======================================
    # SUMMARY TESTS
    # ======================================

    def test_risk_summary(self):

        results = analyze_risks(self.audit_results)

        summary = get_risk_summary(results)

        self.assertEqual(summary["HIGH"], 1)
        self.assertEqual(summary["LOW"], 2)
        self.assertEqual(summary["INFORMATIONAL"], 1)
        self.assertEqual(summary["MEDIUM"], 0)
        self.assertEqual(summary["UNDETERMINED"], 0)

    def test_summary_handles_unknown_risk_level(self):

        summary = get_risk_summary([
            {"risk_level": "CRITICAL"},
            {"risk_level": "HIGH"}
        ])

        self.assertEqual(summary["HIGH"], 1)
        self.assertEqual(summary["UNDETERMINED"], 1)

    # ======================================
    # INPUT VALIDATION TESTS
    # ======================================

    def test_reject_non_list_audit_results(self):

        with self.assertRaises(TypeError):
            analyze_risks("invalid data")

    def test_reject_invalid_audit_record(self):

        with self.assertRaises(ValueError):
            analyze_risks([
                "invalid record"
            ])

    def test_reject_non_list_risk_summary(self):

        with self.assertRaises(TypeError):
            get_risk_summary("invalid data")

    # ======================================
    # METHODOLOGY TEST
    # ======================================

    def test_risk_methodology(self):

        methodology = get_risk_methodology()

        self.assertEqual(
            methodology["method"],
            "AUDITRON Rule-Based Risk Scoring"
        )

        self.assertIn(
            "CVSS",
            methodology["limitation"]
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
