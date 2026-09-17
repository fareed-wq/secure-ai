import pytest
from unittest.mock import MagicMock, patch
import requests
from api.scanner.transport import safe_request
from api.scanner.modules.headers import PermissionsPolicyModule

@patch('api.scanner.transport.is_public_hostname')
@patch('requests.Session.request')
def test_safe_request_no_redirect(mock_req, mock_is_public):
    mock_is_public.return_value = True

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_redirect = False
    mock_resp.headers = {'Content-Type': 'text/html'}
    mock_req.return_value = mock_resp

    session = requests.Session()
    resp = safe_request('GET', 'http://example.com', session=session)

    assert resp.history == []
    assert resp.status_code == 200
    assert resp.headers['Content-Type'] == 'text/html'

@patch('api.scanner.transport.is_public_hostname')
@patch('requests.Session.request')
def test_safe_request_one_redirect(mock_req, mock_is_public):
    mock_is_public.return_value = True

    resp_301 = MagicMock()
    resp_301.status_code = 301
    resp_301.is_redirect = True
    resp_301.headers = {'Location': 'https://example.com', 'X-Redirect': 'true'}

    resp_200 = MagicMock()
    resp_200.status_code = 200
    resp_200.is_redirect = False
    resp_200.headers = {'Content-Type': 'text/html', 'X-Final': 'true'}

    mock_req.side_effect = [resp_301, resp_200]

    session = requests.Session()
    resp = safe_request('GET', 'http://example.com', session=session)

    assert len(resp.history) == 1
    assert resp.history[0].status_code == 301
    assert resp.history[0].headers['X-Redirect'] == 'true'
    assert resp.status_code == 200
    # Final headers remain final
    assert 'X-Final' in resp.headers
    assert 'X-Redirect' not in resp.headers
    # Accumulated headers available
    assert 'X-Redirect' in resp.all_headers
    assert 'X-Final' in resp.all_headers
    assert 'Location' in resp.all_headers
    # Response was closed
    resp_301.close.assert_called_once()

@patch('api.scanner.transport.is_public_hostname')
@patch('requests.Session.request')
def test_safe_request_multiple_redirects(mock_req, mock_is_public):
    mock_is_public.return_value = True

    resp_301 = MagicMock()
    resp_301.status_code = 301
    resp_301.is_redirect = True
    resp_301.headers = {'Location': 'https://example.com'}

    resp_302 = MagicMock()
    resp_302.status_code = 302
    resp_302.is_redirect = True
    resp_302.headers = {'Location': 'https://www.example.com'}

    resp_200 = MagicMock()
    resp_200.status_code = 200
    resp_200.is_redirect = False
    resp_200.headers = {}

    mock_req.side_effect = [resp_301, resp_302, resp_200]

    session = requests.Session()
    resp = safe_request('GET', 'http://example.com', session=session)

    assert len(resp.history) == 2
    assert [r.status_code for r in resp.history] == [301, 302]
    resp_301.close.assert_called_once()
    resp_302.close.assert_called_once()


@patch('api.scanner.modules.headers.safe_request')
def test_permissions_policy_redirect_only(mock_safe_req):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    # The final response does NOT have the header
    mock_resp.headers = {'Content-Type': 'text/html'}
    # The accumulated headers DO have the header
    mock_resp.all_headers = {'Permissions-Policy': 'camera=()', 'Content-Type': 'text/html'}

    mock_safe_req.return_value = mock_resp

    mod = PermissionsPolicyModule()
    session = MagicMock()
    findings = mod.run('http://example.com', 'example.com', session)

    assert any(f['rule_id'] == 'headers_permissions_policy_missing' for f in findings)
    assert not any(f['rule_id'] == 'headers_permissions_policy_configured' for f in findings)


@patch('api.scanner.modules.headers.safe_request')
def test_permissions_policy_final_only(mock_safe_req):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {'Permissions-Policy': 'camera=()', 'Content-Type': 'text/html'}
    mock_resp.all_headers = {'Permissions-Policy': 'camera=()', 'Content-Type': 'text/html'}

    mock_safe_req.return_value = mock_resp

    mod = PermissionsPolicyModule()
    session = MagicMock()
    findings = mod.run('http://example.com', 'example.com', session)

    assert any(f['rule_id'] == 'headers_permissions_policy_configured' for f in findings)
    assert not any(f['rule_id'] == 'headers_permissions_policy_missing' for f in findings)

@patch('api.scanner.modules.headers.safe_request')
def test_permissions_policy_different_value_redirect_final(mock_safe_req):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {'Permissions-Policy': 'camera=()', 'Content-Type': 'text/html'}
    # Accumulated would have whatever overwrote what (e.g. final overwrites 301, but the test ensures we use final)
    mock_resp.all_headers = {'Permissions-Policy': 'geolocation=()', 'Content-Type': 'text/html'}

    mock_safe_req.return_value = mock_resp

    mod = PermissionsPolicyModule()
    session = MagicMock()
    findings = mod.run('http://example.com', 'example.com', session)

    finding = next(f for f in findings if f['rule_id'] == 'headers_permissions_policy_configured')
    assert finding['evidence'].get('raw', finding['evidence']) == 'camera=()'
