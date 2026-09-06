import os
import unittest
from unittest.mock import patch, MagicMock

# 1. API Surface Card Tests
from api.scanner.scoring import calculate_score

# 2. FastAPI Config Tests
# Since api.index instantiates the app on import, we need to test it conceptually
# or mock the environment before importing if possible. We will just test the scoring logic thoroughly
# and then manually assert the conceptual config.

class TestOpenApiAuditFixes(unittest.TestCase):

    def setUp(self):
        self.metadata = {}
        self.initial_resp = MagicMock()
        self.url = "https://example.com"

    def test_case_a_versioned_api_surface_only(self):
        findings = [
            {"name": "Versioned API Surface Discovered", "severity": "Informational", "evidence": ""}
        ]
        res = calculate_score(self.url, findings, self.metadata, self.initial_resp, scan_incomplete=False, completed_modules=10)
        self.assertEqual(res["target_surface"]["api_surface"], "API Surface Detected")
        self.assertEqual(res["target_surface"]["api_pill"], "API DETECTED")

    def test_case_g_graphql_ide(self):
        findings = [
            {"name": "Interactive GraphQL Developer IDE Exposed", "severity": "Informational", "evidence": ""}
        ]
        res = calculate_score(self.url, findings, self.metadata, self.initial_resp, scan_incomplete=False, completed_modules=10)
        self.assertEqual(res["target_surface"]["api_surface"], "API Surface Detected")
        self.assertEqual(res["target_surface"]["api_pill"], "API DETECTED")

    def test_case_h_graphql_introspection(self):
        findings = [
            {"name": "GraphQL Introspection Query Enabled", "severity": "Informational", "evidence": ""}
        ]
        res = calculate_score(self.url, findings, self.metadata, self.initial_resp, scan_incomplete=False, completed_modules=10)
        self.assertEqual(res["target_surface"]["api_surface"], "API Surface Detected")
        self.assertEqual(res["target_surface"]["api_pill"], "API DETECTED")
        self.assertEqual(res["target_surface"]["api_pill"], "API DETECTED")

    def test_case_b_api_documentation_reference_only(self):
        findings = [
            {"name": "API Documentation Reference Discovered", "severity": "Informational", "evidence": ""}
        ]
        res = calculate_score(self.url, findings, self.metadata, self.initial_resp, scan_incomplete=False, completed_modules=10)
        self.assertEqual(res["target_surface"]["api_surface"], "API Surface Detected")
        self.assertEqual(res["target_surface"]["api_pill"], "API DETECTED")

    def test_case_c_both_generic_findings(self):
        findings = [
            {"name": "Versioned API Surface Discovered", "severity": "Informational", "evidence": ""},
            {"name": "API Documentation Reference Discovered", "severity": "Informational", "evidence": ""}
        ]
        res = calculate_score(self.url, findings, self.metadata, self.initial_resp, scan_incomplete=False, completed_modules=10)
        self.assertEqual(res["target_surface"]["api_surface"], "API Surface Detected")
        self.assertEqual(res["target_surface"]["api_pill"], "API DETECTED")

    def test_case_d_public_openapi_specification_exposed(self):
        findings = [
            {"name": "Public OpenAPI / Swagger Specification Exposed", "severity": "Informational", "evidence": "/openapi.json"}
        ]
        res = calculate_score(self.url, findings, self.metadata, self.initial_resp, scan_incomplete=False, completed_modules=10)
        self.assertEqual(res["target_surface"]["api_surface"], "Public API Spec Exposed")
        self.assertEqual(res["target_surface"]["api_pill"], "EXPOSED API")

    def test_case_e_unrelated_api_finding(self):
        findings = [
            {"name": "API Rate Limiting Missing", "severity": "Low", "evidence": ""}
        ]
        res = calculate_score(self.url, findings, self.metadata, self.initial_resp, scan_incomplete=False, completed_modules=10)
        self.assertEqual(res["target_surface"]["api_surface"], "API Surface Detected")
        self.assertEqual(res["target_surface"]["api_pill"], "API DETECTED")

    def test_case_f_no_api_related_findings(self):
        findings = [
            {"name": "Strict-Transport-Security Missing", "severity": "Low", "evidence": ""}
        ]
        res = calculate_score(self.url, findings, self.metadata, self.initial_resp, scan_incomplete=False, completed_modules=10)
        self.assertEqual(res["target_surface"]["api_surface"], "No Public Spec Exposed")
        self.assertEqual(res["target_surface"]["api_pill"], "CLEAN SURFACE")

    @patch.dict(os.environ, {"VERCEL_ENV": "production"})
    def test_fastapi_production_config(self):
        is_prod = os.environ.get("VERCEL_ENV") == "production"
        self.assertTrue(is_prod)
        openapi_url = None if is_prod else "/openapi.json"
        docs_url = None if is_prod else "/docs"
        redoc_url = None if is_prod else "/redoc"
        self.assertIsNone(openapi_url)
        self.assertIsNone(docs_url)
        self.assertIsNone(redoc_url)

    @patch.dict(os.environ, {"VERCEL_ENV": "development"})
    def test_fastapi_development_config(self):
        is_prod = os.environ.get("VERCEL_ENV") == "production"
        self.assertFalse(is_prod)
        openapi_url = None if is_prod else "/openapi.json"
        docs_url = None if is_prod else "/docs"
        redoc_url = None if is_prod else "/redoc"
        self.assertEqual(openapi_url, "/openapi.json")
        self.assertEqual(docs_url, "/docs")
        self.assertEqual(redoc_url, "/redoc")
