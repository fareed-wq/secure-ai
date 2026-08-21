import unittest
from unittest.mock import patch, MagicMock

import requests
from api.scanner.base import ScannerModule
from api.scanner.scoring import calculate_score
from api.scanner.modules.headers import CORSModule
from api.scanner.modules.network_checks import SubdomainTakeoverModule, PassiveSubdomainDiscoveryModule

class DummyModule(ScannerModule):
    module_name = "Dummy"
    description = "Dummy"
    def run(self, url, hostname, session):
        return []

class TestPhase24Consistency(unittest.TestCase):
    def test_schema_severity_confidence(self):
        mod = DummyModule()
        valid_sevs = {"Critical", "High", "Medium", "Low", "Informational", "Passed"}
        valid_confs = {"High", "Medium", "Low", "Informational"}
        
        f = mod.make_finding("Test", "High", "Desc", "Ev", confidence="Medium", owasp="A01")
        self.assertIn(f["severity"], valid_sevs)
        self.assertIn(f["confidence"], valid_confs)
        self.assertNotEqual(f["evidence"], "")

    def test_empty_evidence_prevention(self):
        # We manually verify that the replaced empty evidences aren't empty
        import ast
        import glob
        import os
        files = glob.glob("api/scanner/modules/*.py")
        for fpath in files:
            with open(fpath, "r", encoding="utf-8") as f:
                code = f.read()
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute) and node.func.attr == "make_finding":
                        if len(node.args) >= 4 and isinstance(node.args[3], ast.Constant):
                            ev = node.args[3].value
                            self.assertNotEqual(ev, "", f"Found empty evidence in {fpath}")
                            
    @patch("api.scanner.modules.headers.safe_request")
    def test_phase23_cors_confidence(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.headers = {"Access-Control-Allow-Origin": "*"}
        mock_resp.status_code = 200
        mock_req.return_value = mock_resp
        
        mod = CORSModule()
        findings = mod.run("http://test.com", "test.com", requests.Session())
        for f in findings:
            if "Potential CORS Misconfiguration" in f["name"]:
                self.assertEqual(f["confidence"], "Medium")

    @patch("api.scanner.modules.discovery.safe_request")
    def test_phase23_admin_confidence(self, mock_req):
        mock_resp_home = MagicMock()
        mock_resp_home.status_code = 200
        mock_resp_home.text = "homepage"
        mock_resp_home.headers = {"Content-Type": "text/html"}
        
        mock_resp_admin = MagicMock()
        mock_resp_admin.status_code = 200
        mock_resp_admin.text = 'type="password" admin login' + " " * 200
        mock_resp_admin.headers = {"Content-Type": "text/html"}
        
        def mock_side_effect(method, url, **kwargs):
            if url.endswith("/admin"):
                return mock_resp_admin
            return mock_resp_home
        
        mock_req.side_effect = mock_side_effect
        
        from api.scanner.modules.discovery import ExposedFilesModule
        mod = ExposedFilesModule()
        findings = mod.run("http://test.com", "test.com", requests.Session())
        f = findings[0]
        self.assertEqual(f["name"], "Administrative Interface Exposed")
        self.assertEqual(f["confidence"], "Medium")

    @patch("api.scanner.modules.network_checks.safe_request")
    def test_phase23_takeover_confidence(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        # Return CNAME first, then probe response
        mock_resp.json.return_value = {"Answer": [{"type": 5, "data": "s3.amazonaws.com."}]}
        mock_resp.text = "NoSuchBucket"
        mock_req.return_value = mock_resp
        
        mod = SubdomainTakeoverModule()
        findings = mod.run("http://test.com", "test.com", requests.Session())
        
        found = False
        for f in findings:
            if "Subdomain Takeover" in f["name"]:
                found = True
                self.assertEqual(f["confidence"], "Medium")
        self.assertTrue(found, "Subdomain Takeover finding not generated")

    def test_score_deduplication(self):
        # Two TLS findings should be deduplicated
        findings = [
            {"name": "Deprecated TLS 1.0/1.1 Supported", "severity": "Medium", "category": "encryption_tls"},
            {"name": "Weak TLS Cipher", "severity": "High", "category": "encryption_tls"}
        ]
        res = calculate_score("http://test.com", findings, {}, None)
        
        # Original findings should be perfectly intact
        self.assertEqual(len(res["findings"]), 2)
        
        # Medium and High should trigger a penalty for High, but only once because they share TLS identity
        # The weight for High is 10. Total score = 90.
        self.assertEqual(res["score"], 90)
        self.assertEqual(res["severity_counts"]["High"], 1)
        self.assertEqual(res["severity_counts"]["Medium"], 1)
        
    def test_informational_zero_penalty(self):
        findings = [
            {"name": "Info 1", "severity": "Informational", "category": "info"},
            {"name": "Info 2", "severity": "Informational", "category": "info"}
        ]
        res = calculate_score("http://test.com", findings, {}, None)
        self.assertEqual(res["score"], 100)
        self.assertEqual(res["severity_counts"]["Informational"], 2)

    def test_evidence_masking(self):
        mod = DummyModule()
        # Secret at beginning
        f1 = mod.make_finding("T", "Low", "D", "sk_live_1234567890abcdefGH " + "a"*200)
        self.assertTrue("[REDACTED_STRIPE]" in f1["evidence"]["raw"])
        self.assertFalse("sk_live" in f1["evidence"]["raw"])
        
        # Secret in middle
        f2 = mod.make_finding("T", "Low", "D", "prefix " + "sk_live_1234567890abcdefGH " + "a"*200)
        self.assertTrue("[REDACTED_STRIPE]" in f2["evidence"]["raw"])
        self.assertFalse("sk_live" in f2["evidence"]["raw"])
        
        # Secret at end
        f3 = mod.make_finding("T", "Low", "D", "a"*150 + " sk_live_1234567890abcdefGH")
        self.assertTrue("[REDACTED_STRIPE]" in f3["evidence"]["raw"])
        self.assertFalse("sk_live" in f3["evidence"]["raw"])
        
        # Secret at truncation boundary
        # If boundary is 180, secret starts at 160
        f4 = mod.make_finding("T", "Low", "D", "a"*160 + " sk_live_1234567890abcdefGH " + "b"*10)
        self.assertTrue("[REDACTED_STRIPE]" in f4["evidence"]["raw"])
        self.assertFalse("sk_live" in f4["evidence"]["raw"])

    def test_owasp_mapping(self):
        # We manually verify that OWASP mappings exist and are correct strings
        import ast
        import glob
        files = glob.glob("api/scanner/modules/*.py")
        for fpath in files:
            with open(fpath, "r", encoding="utf-8") as f:
                code = f.read()
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute) and node.func.attr == "make_finding":
                        owasp_found = False
                        for kw in node.keywords:
                            if kw.arg == "owasp":
                                owasp_found = True
                                if isinstance(kw.value, ast.Constant):
                                    self.assertTrue(kw.value.value.startswith("A0"))
                        self.assertTrue(owasp_found, f"Missing OWASP mapping in {fpath}")

if __name__ == "__main__":
    unittest.main()
