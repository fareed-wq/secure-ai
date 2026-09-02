import unittest
import re
from api.scanner.modules.javascript_security import JavaScriptSecurityModule

class TestJavaScriptApiRoutes(unittest.TestCase):
    def setUp(self):
        self.mod = JavaScriptSecurityModule()

    def _test_route(self, path: str) -> bool:
        """Helper to test if a route matches API_ROUTE_PATTERN"""
        match = self.mod.API_ROUTE_PATTERN.search(f'"{path}"')
        return match is not None

    def _test_seq_id(self, path: str) -> bool:
        """Helper to test if a route triggers seq id"""
        match = self.mod.SEQ_ID_PATTERN.search(path)
        return match is not None

    def test_positive_api_routes(self):
        self.assertTrue(self._test_route("/api/users/123"))
        self.assertTrue(self._test_route("/api/orders/456"))
        self.assertTrue(self._test_route("/api/v1/users/123"))
        self.assertTrue(self._test_route("/rest/accounts/99"))
        self.assertTrue(self._test_route("/api/status"))
        self.assertTrue(self._test_route("/api/users"))

        self.assertTrue(self._test_seq_id("/api/users/123"))
        self.assertTrue(self._test_seq_id("/api/orders/456"))
        self.assertTrue(self._test_seq_id("/api/v1/users/123"))
        self.assertTrue(self._test_seq_id("/rest/accounts/99"))

    def test_negative_api_routes(self):
        self.assertFalse(self._test_route("/blog/2026"))
        self.assertFalse(self._test_route("/products/123"))
        self.assertFalse(self._test_route("/images/123.png"))
        self.assertFalse(self._test_route("/assets/chunk123.js"))
        self.assertFalse(self._test_route("/version/123"))
        self.assertFalse(self._test_route("/users/123"))

    def test_api_routes_without_seq_id(self):
        self.assertTrue(self._test_route("/api/status"))
        self.assertTrue(self._test_route("/api/users"))
        self.assertFalse(self._test_seq_id("/api/status"))
        self.assertFalse(self._test_seq_id("/api/users"))

if __name__ == "__main__":
    unittest.main()
