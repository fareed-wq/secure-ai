import sys

with open('test_scanner_units.py', 'r', encoding='utf-8') as f:
    content = f.read()

new_tests = '''
class TestGraphQLAndStackTraceModules:
    def test_graphql_introspection(self, mock_response_builder, mocker):
        from api.index import GraphQLIntrospectionModule
        import requests
        
        # Mock graphql endpoint response with __typename
        mock_resp = mock_response_builder(status_code=200, text='{"data": {"__schema": {}}}', headers={"Content-Type": "application/json"})
        mocker.patch("api.index.safe_request", return_value=mock_resp)
        
        module = GraphQLIntrospectionModule()
        session = requests.Session()
        findings = module.run("https://countries.trevorblades.com", "countries.trevorblades.com", session)
        
        assert len(findings) > 0, "Expected a finding for GraphQL introspection"
        assert findings[0]["severity"] == "Informational"
        assert "graphql" in findings[0]["name"].lower()

    def test_verbose_stack_trace_leak_positive(self, mock_response_builder, mocker):
        from api.index import VerboseStackTraceModule
        import requests
        
        # Mock API returning 500 with stack trace
        mock_resp = mock_response_builder(status_code=500, text='{"error": "SQLSTATE[23505]: Unique violation"}', headers={"Content-Type": "application/json"})
        mocker.patch("api.index.safe_request", return_value=mock_resp)
        
        module = VerboseStackTraceModule()
        session = requests.Session()
        findings = module.run("https://api.example.com", "api.example.com", session)
        
        assert len(findings) > 0, "Expected a finding for verbose stack trace leak"
        assert findings[0]["severity"] == "Medium"
        assert "verbose backend error" in findings[0]["name"].lower()

    def test_verbose_stack_trace_guardrail_negative(self, mock_response_builder, mocker):
        from api.index import VerboseStackTraceModule
        import requests
        
        # Mock HTML SPA 200 OK response with the signature string inside HTML body (should be ignored)
        mock_resp = mock_response_builder(status_code=200, text='<html><body>SQLSTATE[23505]</body></html>', headers={"Content-Type": "text/html"})
        mocker.patch("api.index.safe_request", return_value=mock_resp)
        
        module = VerboseStackTraceModule()
        session = requests.Session()
        findings = module.run("https://nextjs.org", "nextjs.org", session)
        
        assert len(findings) == 0, "Expected zero findings for HTML/SPA routes (false positive guardrail failed)"

'''

if 'TestGraphQLAndStackTraceModules' not in content:
    content += '\n' + new_tests
    with open('test_scanner_units.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("Unit tests added to test_scanner_units.py!")
else:
    print("Tests already exist!")
