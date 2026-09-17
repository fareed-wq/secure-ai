import pytest
from unittest.mock import MagicMock, patch
from api.scanner.modules.http_security import SecurityHeadersModule

@patch('api.scanner.modules.http_security.safe_request')
def test_server_nginx_no_waf(mock_safe_req):
    mod = SecurityHeadersModule()
    mock_resp = MagicMock()
    mock_resp.headers = {'Server': 'nginx'}
    mock_safe_req.return_value = mock_resp

    findings = mod.run('http://example.com', 'example.com', session=MagicMock())

    waf_active = next((f for f in findings if f['rule_id'] == 'headers_waf_active'), None)
    waf_missing = next((f for f in findings if f['rule_id'] == 'headers_waf_missing'), None)

    assert waf_active is None
    assert waf_missing is not None
    assert waf_missing['severity'] == 'Informational'

@patch('api.scanner.modules.http_security.safe_request')
def test_server_apache_no_waf(mock_safe_req):
    mod = SecurityHeadersModule()
    mock_resp = MagicMock()
    mock_resp.headers = {'Server': 'Apache'}
    mock_safe_req.return_value = mock_resp
    findings = mod.run('http://example.com', 'example.com', session=MagicMock())
    assert not any(f['rule_id'] == 'headers_waf_active' for f in findings)

@patch('api.scanner.modules.http_security.safe_request')
def test_server_gws_no_waf(mock_safe_req):
    mod = SecurityHeadersModule()
    mock_resp = MagicMock()
    mock_resp.headers = {'Server': 'gws'}
    mock_safe_req.return_value = mock_resp
    findings = mod.run('http://example.com', 'example.com', session=MagicMock())
    assert not any(f['rule_id'] == 'headers_waf_active' for f in findings)
    assert any(f['rule_id'] == 'headers_waf_missing' for f in findings)

@patch('api.scanner.modules.http_security.safe_request')
def test_server_iis_no_waf(mock_safe_req):
    mod = SecurityHeadersModule()
    mock_resp = MagicMock()
    mock_resp.headers = {'Server': 'Microsoft-IIS'}
    mock_safe_req.return_value = mock_resp
    findings = mod.run('http://example.com', 'example.com', session=MagicMock())
    assert not any(f['rule_id'] == 'headers_waf_active' for f in findings)

@patch('api.scanner.modules.http_security.safe_request')
def test_server_cloudflare_is_detected(mock_safe_req):
    mod = SecurityHeadersModule()
    mock_resp = MagicMock()
    mock_resp.headers = {'Server': 'cloudflare'}
    mock_safe_req.return_value = mock_resp
    findings = mod.run('http://example.com', 'example.com', session=MagicMock())

    waf_active = next((f for f in findings if f['rule_id'] == 'headers_waf_active'), None)
    assert waf_active is not None
    assert waf_active['name'] == 'Potential WAF / Security Edge Detected'
    assert waf_active['severity'] == 'Informational'
    assert waf_active['evidence'].get('raw', waf_active['evidence']).lower() == 'server: cloudflare'

@patch('api.scanner.modules.http_security.safe_request')
def test_cf_ray_is_detected(mock_safe_req):
    mod = SecurityHeadersModule()
    mock_resp = MagicMock()
    mock_resp.headers = {'CF-Ray': '123456789-DFW'}
    mock_safe_req.return_value = mock_resp
    findings = mod.run('http://example.com', 'example.com', session=MagicMock())

    waf_active = next((f for f in findings if f['rule_id'] == 'headers_waf_active'), None)
    assert waf_active is not None
    assert waf_active['evidence'].get('raw', waf_active['evidence']).lower() == 'cf-ray: 123456789-dfw'

@patch('api.scanner.modules.http_security.safe_request')
def test_x_cdn_is_detected(mock_safe_req):
    mod = SecurityHeadersModule()
    mock_resp = MagicMock()
    mock_resp.headers = {'X-CDN': 'Incapsula'}
    mock_safe_req.return_value = mock_resp
    findings = mod.run('http://example.com', 'example.com', session=MagicMock())

    waf_active = next((f for f in findings if f['rule_id'] == 'headers_waf_active'), None)
    assert waf_active is not None
    assert waf_active['name'] == 'Potential WAF / Security Edge Detected'
    assert 'passive detection cannot confirm' in waf_active['description'].lower()

@patch('api.scanner.modules.http_security.safe_request')
def test_awsalb_is_detected(mock_safe_req):
    mod = SecurityHeadersModule()
    mock_resp = MagicMock()
    mock_resp.headers = {'awsalb': 'some-aws-token'}
    mock_safe_req.return_value = mock_resp
    findings = mod.run('http://example.com', 'example.com', session=MagicMock())

    waf_active = next((f for f in findings if f['rule_id'] == 'headers_waf_active'), None)
    assert waf_active is not None
    assert waf_active['name'] == 'Potential WAF / Security Edge Detected'

@patch('api.scanner.modules.http_security.safe_request')
def test_no_relevant_signals(mock_safe_req):
    mod = SecurityHeadersModule()
    mock_resp = MagicMock()
    mock_resp.headers = {'Content-Type': 'text/html'}
    mock_safe_req.return_value = mock_resp
    findings = mod.run('http://example.com', 'example.com', session=MagicMock())

    waf_missing = next((f for f in findings if f['rule_id'] == 'headers_waf_missing'), None)
    assert waf_missing is not None
    assert waf_missing['severity'] == 'Informational'

def test_compare_severity_logic():
    from api.scanner.compare import _get_severity_weight
    assert _get_severity_weight('Passed') == 0
    assert _get_severity_weight('Informational') == 0
