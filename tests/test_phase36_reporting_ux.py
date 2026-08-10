import unittest
import copy
from api.scanner.scoring import calculate_score
from api.scanner.base import ScannerModule
class DummyModule(ScannerModule):
    @property
    def name(self) -> str:
        return "DummyModule"
    def run(self, url: str) -> list:
        return []

class TestPhase36ReportingUX(unittest.TestCase):
    def setUp(self):
        self.dummy = DummyModule()
        self.sample_findings = [
            self.dummy.make_finding(
                name="Missing Security Header",
                severity="Medium",
                category="HTTP Headers",
                description="A security header is missing.",
                remediation="Add the header.",
                impact="Medium impact.",
                evidence="Raw evidence here",
                domain="browser_defense"
            ),
            self.dummy.make_finding(
                name="Strict-Transport-Security Missing",
                severity="High",
                category="HTTP Headers",
                description="HSTS is missing.",
                remediation="Add HSTS.",
                impact="High impact.",
                evidence="No HSTS",
                domain="transport_tls"
            ),
            self.dummy.make_finding(
                name="Valid TLS",
                severity="Passed",
                category="Encryption",
                description="TLS is valid.",
                remediation="N/A",
                impact="N/A",
                evidence="TLS 1.3",
                domain="transport_tls"
            ),
            self.dummy.make_finding(
                name="Secret Key Exposed",
                severity="Critical",
                category="Secret Exposure",
                description="A secret key was found.",
                remediation="Remove the secret.",
                impact="Critical impact.",
                evidence="Found token: sk_live_51J...",  # Should be masked by base.py if this was a real module, but here we test immutability
                domain="api_surface"
            )
        ]
        
    def test_score_and_grade_consistency(self):
        """Test that the score remains consistent across repeated calls and deduplication works."""
        findings_copy = copy.deepcopy(self.sample_findings)
        
        report1 = calculate_score("https://example.com", findings_copy, {}, None)
        score1 = report1['score']
        
        # Test that score is consistent
        self.assertIsInstance(score1, int)
        self.assertTrue(0 <= score1 <= 100)
        
        # Calculate again with exact same findings
        report2 = calculate_score("https://example.com", findings_copy, {}, None)
        score2 = report2['score']
        self.assertEqual(score1, score2)
        
        # Verify deduplication - add duplicate finding
        duplicate_finding = self.dummy.make_finding(
            name="Missing Security Header",
            severity="Medium",
            category="HTTP Headers",
            description="A security header is missing.",
            remediation="Add the header.",
            impact="Medium impact.",
            evidence="Different raw evidence here",
            domain="browser_defense"
        )
        findings_with_dupe = copy.deepcopy(self.sample_findings) + [duplicate_finding]
        
        report3 = calculate_score("https://example.com", findings_with_dupe, {}, None)
        score3 = report3['score']
        # Score should be the same despite duplicate because of identity deduplication
        self.assertEqual(score1, score3)

    def test_report_immutability(self):
        """Test that calculating the score does not mutate the original findings."""
        findings_copy = copy.deepcopy(self.sample_findings)
        original_findings = copy.deepcopy(self.sample_findings)
        
        report = calculate_score("https://example.com", findings_copy, {}, None)
        
        # Ensure the list of findings and the contents are unchanged
        self.assertEqual(len(findings_copy), len(original_findings))
        for i in range(len(findings_copy)):
            self.assertEqual(findings_copy[i]['severity'], original_findings[i]['severity'])
            self.assertEqual(findings_copy[i]['evidence'], original_findings[i]['evidence'])

    def test_secret_masking(self):
        """Verify that make_finding properly masks secrets before storing them."""
        raw_evidence = "My API key is sk_live_51J8xyz and token is ghp_1234567890abcdefghij1234567890abcdef"
        
        finding = self.dummy.make_finding(
            name="Secret Test",
            severity="High",
            category="Secrets",
            description="Testing masking",
            remediation="N/A",
            impact="N/A",
            evidence=raw_evidence,
            domain="api_surface"
        )
        
        # Evidence should be masked
        evidence_str = finding['evidence']['raw'] if isinstance(finding['evidence'], dict) and 'raw' in finding['evidence'] else str(finding['evidence'])
        self.assertNotIn("sk_live_51J8xyz", evidence_str)
        self.assertNotIn("ghp_1234567890abcdefghij1234567890abcdef", evidence_str)
        self.assertIn("[REDACTED_STRIPE]", evidence_str)
        self.assertIn("[REDACTED_GITHUB]", evidence_str)

if __name__ == '__main__':
    unittest.main()
