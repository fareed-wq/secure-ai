import pytest
from unittest.mock import MagicMock, patch
import requests

# Import engine registered modules
try:
    from api.index import REGISTERED_MODULES, ScannerModule
except ImportError:
    from index import REGISTERED_MODULES, ScannerModule

# ---------------------------------------------------------------------------
# 🛠️ PYTEST FIXTURES & MOCK GENERATORS
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_response_builder():
    """Factory fixture to build standard mock requests.Response objects."""
    def _create_response(status_code=200, text="", headers=None, json_data=None, url="https://example.com"):
        resp = MagicMock(spec=requests.Response)
        resp.status_code = status_code
        resp.text = text
        resp.content = text.encode("utf-8")
        resp.headers = headers or {}
        resp.url = url
        if json_data is not None:
            resp.json.return_value = json_data
        return resp
    return _create_response


@pytest.fixture
def mock_session(mock_response_builder):
    """Mocks requests.Session to prevent actual network calls."""
    session = MagicMock(spec=requests.Session)
    
    # Default baseline response (Simulating a standard clean homepage)
    default_resp = mock_response_builder(
        status_code=200,
        text="<html><head><title>Test Baseline Target</title></head><body>Welcome</body></html>",
        headers={"Content-Type": "text/html; charset=utf-8", "Server": "Vercel"}
    )
    session.get.return_value = default_resp
    session.request.return_value = default_resp
    return session


# ---------------------------------------------------------------------------
# 🧪 MODULE UNIT TESTS (OFFLINE)
# ---------------------------------------------------------------------------

class TestHeaderModules:
    """Tests all Security Header & Cookie modules offline."""

    def test_security_headers_missing(self, mock_session, mock_response_builder):
        # Mock response missing CSP and HSTS
        resp = mock_response_builder(status_code=200, headers={"Server": "nginx"})
        mock_session.get.return_value = resp

        # Find SecurityHeadersModule
        module = next(m for m in REGISTERED_MODULES if m.module_name == "SecurityHeaders")
        findings = module.run("https://example.com", "example.com", mock_session)

        assert any("hsts" in f["name"].lower() or "strict-transport" in f["name"].lower() for f in findings)
        assert any("csp" in f["name"].lower() or "content-security" in f["name"].lower() for f in findings)

    def test_cors_wildcard_reflection(self, mock_session, mock_response_builder):
        # Mock response reflecting untrusted origin
        resp = mock_response_builder(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": "https://evil.com",
                "Access-Control-Allow-Credentials": "true"
            },
            url="https://example.com"
        )
        mock_session.get.return_value = resp
        mock_session.request.return_value = resp

        module = next(m for m in REGISTERED_MODULES if m.module_name == "CORS")
        findings = module.run("https://example.com", "example.com", mock_session)

        assert len(findings) > 0
        assert any("cors" in f["name"].lower() for f in findings)


class TestFileAndPathModules:
    """Tests Exposed Files, SPA Soft-404 Guards, and Sensitive Paths."""

    def test_spa_soft_404_guard_prevents_false_positives(self, mock_session, mock_response_builder):
        # Simulate React/Next.js SPA returning homepage text for /.env
        homepage_text = "<html><body>SPA Root Page</body></html>"
        
        # When fetching homepage or /.env, return identical HTML length
        spa_resp = mock_response_builder(status_code=200, text=homepage_text, headers={"Content-Type": "text/html"})
        mock_session.get.return_value = spa_resp

        module = next((m for m in REGISTERED_MODULES if m.module_name == "ExposedFiles"), None)
        if module:
            findings = module.run("https://example.com", "example.com", mock_session)
            # Must NOT report exposed .env file due to is_spa_fallback guard
            assert not any(f.get("status", f.get("severity", "")) in ["High", "Critical"] and ".env" in f["name"] for f in findings)

    def test_real_exposed_env_file_detection(self, mock_session, mock_response_builder):
        # Mock actual raw .env content
        env_content = "DB_HOST=127.0.0.1\nDB_PASSWORD=secret_pass_123\nAPP_KEY=base64:xyz"
        env_resp = mock_response_builder(status_code=200, text=env_content, headers={"Content-Type": "text/plain"}, url="https://example.com/.env")
        baseline_resp = mock_response_builder(status_code=200, text="<html>" + "a"*500 + "</html>", url="https://example.com")
        
        def _get_side_effect(*args, **kwargs):
            # Handle session.request("GET", url) vs session.get(url)
            if len(args) > 1 and args[0] in ["GET", "POST", "HEAD"]:
                target_url = args[1]
            elif args:
                target_url = args[0]
            else:
                target_url = kwargs.get("url", "")

            # Route request to correct mock response based on endpoint
            if ".env" in target_url:
                return env_resp
            return baseline_resp
            
        mock_session.get.side_effect = _get_side_effect
        mock_session.request.side_effect = _get_side_effect

        module = next((m for m in REGISTERED_MODULES if m.module_name == "ExposedFiles"), None)
        if module:
            findings = module.run("https://example.com", "example.com", mock_session)
            assert any(f.get("status", f.get("severity", "")) in ["High", "Critical"] for f in findings)


class TestDNSModules:
    """Tests DNS CAA, SPF/DMARC, and Subdomain Takeover modules via mocked DoH."""

    def test_dmarc_missing_policy_alert(self, mock_session, mock_response_builder):
        # Mock Google DoH JSON response with empty TXT records
        doh_empty = mock_response_builder(status_code=200, json_data={"Status": 0, "Answer": []})
        mock_session.get.return_value = doh_empty

        module = next(m for m in REGISTERED_MODULES if m.module_name in ["DNSEmailSecurity", "EmailSecurity"])
        findings = module.run("https://example.com", "example.com", mock_session)

        assert any("dmarc" in f["name"].lower() or "spf" in f["name"].lower() for f in findings)

    def test_subdomain_takeover_passed_apex(self, mock_session, mock_response_builder):
        # Mock DoH response confirming NO CNAME (Status = 0, no Answer array)
        doh_no_cname = mock_response_builder(status_code=200, json_data={"Status": 0})
        mock_session.get.return_value = doh_no_cname

        module = next(m for m in REGISTERED_MODULES if m.module_name == "SubdomainTakeover")
        findings = module.run("https://example.com", "github.com", mock_session)

        assert len(findings) == 1
        assert findings[0].get("status", findings[0].get("severity", "")) == "Passed"


class TestSecretScanningModules:
    """Tests JavaScript bundle analysis for private API key leaks."""

    def test_js_bundle_secret_scanner(self, mock_session, mock_response_builder):
        # Mock HTML referencing a JS bundle
        html_resp = mock_response_builder(status_code=200, text='<html><script src="/app.js"></script></html>', url="https://example.com")
        
        # Mock JS bundle containing an AWS Access Key (make sure it's not the exact 'EXAMPLE' key that gets filtered)
        js_code = "const config = { awsKey: 'AKIAIOSFODNN7REALKEY', StripeKey: 'test_key_123456789012345678901234' };"
        js_resp = mock_response_builder(status_code=200, text=js_code, headers={"Content-Type": "application/javascript"}, url="https://example.com/app.js")
        
        def _get_side_effect(url, *args, **kwargs):
            if "app.js" in url:
                return js_resp
            return html_resp
            
        mock_session.get.side_effect = _get_side_effect
        mock_session.request.side_effect = _get_side_effect

        module = next((m for m in REGISTERED_MODULES if m.module_name == "JSBundleSecrets"), None)
        if module:
            findings = module.run("https://example.com", "example.com", mock_session)
            assert any("AWS" in f["name"] or "Stripe" in f["name"] or "Secret" in f["name"] for f in findings)


# ---------------------------------------------------------------------------
# ⚡ GLOBAL SUITE SWEEP (Executes ALL 20+ Modules in Parallel Offline)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("module", REGISTERED_MODULES)
def test_all_modules_run_without_exceptions(module, mock_session):
    """
    Parametrized test that executes every registered module against a mocked
    target to verify zero runtime crashes, syntax errors, or unhandled exceptions.
    """
    try:
        findings = module.run("https://example.com", "example.com", mock_session)
        assert isinstance(findings, list)
    except Exception as exc:
        pytest.fail(f"Module '{module.module_name}' crashed with exception: {exc}")


class TestGraphQLAndStackTraceModules:
    def test_graphql_introspection(self, mock_response_builder, monkeypatch):
        from api.index import GraphQLIntrospectionModule
        import requests
        
        # Mock graphql endpoint response with __typename
        mock_resp = mock_response_builder(status_code=200, text='{"data": {"__schema": {}}}', headers={"Content-Type": "application/json"})
        monkeypatch.setattr("api.index.safe_request", lambda *args, **kwargs: mock_resp)
        
        module = GraphQLIntrospectionModule()
        session = requests.Session()
        findings = module.run("https://countries.trevorblades.com", "countries.trevorblades.com", session)
        
        assert len(findings) > 0, "Expected a finding for GraphQL introspection"
        assert findings[0]["severity"] == "Informational"
        assert "graphql" in findings[0]["name"].lower()

    def test_verbose_stack_trace_leak_positive(self, mock_response_builder, monkeypatch):
        from api.index import VerboseStackTraceModule
        import requests
        
        # Mock API returning 500 with stack trace
        mock_resp = mock_response_builder(status_code=500, text='{"error": "SQLSTATE[23505]: Unique violation"}', headers={"Content-Type": "application/json"})
        monkeypatch.setattr("api.index.safe_request", lambda *args, **kwargs: mock_resp)
        
        module = VerboseStackTraceModule()
        session = requests.Session()
        findings = module.run("https://api.example.com", "api.example.com", session)
        
        assert len(findings) > 0, "Expected a finding for verbose stack trace leak"
        assert findings[0]["severity"] == "Medium"
        assert "verbose backend error" in findings[0]["name"].lower()

    def test_verbose_stack_trace_guardrail_negative(self, mock_response_builder, monkeypatch):
        from api.index import VerboseStackTraceModule
        import requests
        
        # Mock HTML SPA 200 OK response with the signature string inside HTML body (should be ignored)
        mock_resp = mock_response_builder(status_code=200, text='<html><body>SQLSTATE[23505]</body></html>', headers={"Content-Type": "text/html"})
        monkeypatch.setattr("api.index.safe_request", lambda *args, **kwargs: mock_resp)
        
        module = VerboseStackTraceModule()
        session = requests.Session()
        findings = module.run("https://nextjs.org", "nextjs.org", session)
        
        assert len(findings) == 0, "Expected zero findings for HTML/SPA routes (false positive guardrail failed)"

