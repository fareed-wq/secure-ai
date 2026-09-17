import pytest
from unittest.mock import MagicMock, patch
from api.scanner.modules.javascript_security import JavaScriptSecurityModule

@patch('api.scanner.modules.javascript_security.safe_request')
def run_module(mock_safe_req, js_content):
    mod = JavaScriptSecurityModule()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = js_content
    mock_resp.headers = {'Content-Type': 'application/javascript'}
    page_resp = MagicMock()
    page_resp.status_code = 200
    page_resp.text = '<script src="http://example.com/app.js"></script>'
    page_resp.headers = {'Content-Type': 'text/html'}
    mock_safe_req.side_effect = [page_resp, mock_resp]
    return mod.run('http://example.com', 'example.com', session=MagicMock())

# TRUE POSITIVES
def test_api_v1_users():
    findings = run_module(js_content='/api/v1/users')
    assert any(f['rule_id'] == 'js_versioned_api_surface' for f in findings)

def test_api_v2_orders():
    findings = run_module(js_content='/api/v2/orders')
    assert any(f['rule_id'] == 'js_versioned_api_surface' for f in findings)

def test_rest_v1_items():
    findings = run_module(js_content='/rest/v1/items')
    assert any(f['rule_id'] == 'js_versioned_api_surface' for f in findings)

def test_graphql_v2_query():
    findings = run_module(js_content='/graphql/v2/query')
    assert any(f['rule_id'] == 'js_versioned_api_surface' for f in findings)

def test_service_v1_account():
    findings = run_module(js_content='/service/v1/account')
    assert any(f['rule_id'] == 'js_versioned_api_surface' for f in findings)

def test_services_v3_data():
    findings = run_module(js_content='/services/v3/data')
    assert any(f['rule_id'] == 'js_versioned_api_surface' for f in findings)

def test_api_subdomain():
    findings = run_module(js_content='https://api.example.com/v1/users')
    assert any(f['rule_id'] == 'js_versioned_api_surface' for f in findings)

# FALSE POSITIVES
def test_static_v1_app():
    findings = run_module(js_content='/static/v1/app.js')
    assert not any(f['rule_id'] == 'js_versioned_api_surface' for f in findings)

def test_images_v2():
    findings = run_module(js_content='/images/v2/logo.png')
    assert not any(f['rule_id'] == 'js_versioned_api_surface' for f in findings)

def test_assets_v1():
    findings = run_module(js_content='/assets/v1/main.css')
    assert not any(f['rule_id'] == 'js_versioned_api_surface' for f in findings)

def test_libs_v3():
    findings = run_module(js_content='/libs/v3/module.js')
    assert not any(f['rule_id'] == 'js_versioned_api_surface' for f in findings)

def test_foo_v1_bar():
    findings = run_module(js_content='/foo/v1/bar')
    assert not any(f['rule_id'] == 'js_versioned_api_surface' for f in findings)

def test_v1_users():
    findings = run_module(js_content='/v1/users')
    assert not any(f['rule_id'] == 'js_versioned_api_surface' for f in findings)

def test_v2_data():
    findings = run_module(js_content='/v2/data')
    assert not any(f['rule_id'] == 'js_versioned_api_surface' for f in findings)

def test_version_v1():
    findings = run_module(js_content='/version/v1/')
    assert not any(f['rule_id'] == 'js_versioned_api_surface' for f in findings)

def test_myapi_subdomain():
    findings = run_module(js_content='https://myapi.example.com/v1/users')
    assert not any(f['rule_id'] == 'js_versioned_api_surface' for f in findings)

def test_notapi_subdomain():
    findings = run_module(js_content='https://notapi.example.com/v1/users')
    assert not any(f['rule_id'] == 'js_versioned_api_surface' for f in findings)
