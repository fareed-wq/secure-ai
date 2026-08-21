import unittest
from api.scanner.modules.network_checks import GraphQLIntrospectionModule, VerboseStackTraceModule, SubdomainProbingModule
from api.scanner.data.registry import REGISTERED_MODULES
from unittest.mock import patch, MagicMock

class TestPhase16Fixes(unittest.TestCase):
    def test_graphql_module_name(self):
        mod = GraphQLIntrospectionModule()
        self.assertNotEqual(mod.module_name, "BaseModule")
        self.assertEqual(mod.module_name, "GraphQLIntrospection")

    def test_verbose_stack_trace_module_name(self):
        mod = VerboseStackTraceModule()
        self.assertNotEqual(mod.module_name, "BaseModule")
        self.assertEqual(mod.module_name, "VerboseStackTrace")

    def test_subdomain_probing_dynamic_inclusion(self):
        # Check that it's not in REGISTERED_MODULES
        is_registered = any(isinstance(m, SubdomainProbingModule) for m in REGISTERED_MODULES)
        self.assertFalse(is_registered, "SubdomainProbingModule should NOT be in REGISTERED_MODULES")

    @patch('api.scanner.orchestrator.get_metadata')
    @patch('api.scanner.orchestrator.check_liveness')
    @patch('api.scanner.orchestrator.is_public_hostname')
    @patch('api.scanner.orchestrator.safe_request')
    def test_subdomain_probing_orchestrator_inclusion(self, mock_safe_request, mock_public, mock_liveness, mock_metadata):
        # Just verifying it doesn't crash and we can import the orchestrator properly
        from api.scanner.orchestrator import scan_url
        mock_public.return_value = False
        res = scan_url("http://example.com")
        self.assertIn("error", res)

if __name__ == '__main__':
    unittest.main()
