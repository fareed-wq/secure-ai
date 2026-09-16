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

# ARIA FALSE POSITIVES
def test_role_button():
    findings = run_module(js_content='role:"button"')
    assert not any(f['rule_id'] == 'js_auth_roles_disclosed' for f in findings)

def test_role_dialog():
    findings = run_module(js_content='role:"dialog"')
    assert not any(f['rule_id'] == 'js_auth_roles_disclosed' for f in findings)

def test_role_navigation():
    findings = run_module(js_content='role:"navigation"')
    assert not any(f['rule_id'] == 'js_auth_roles_disclosed' for f in findings)

def test_role_menu():
    findings = run_module(js_content='role:"menu"')
    assert not any(f['rule_id'] == 'js_auth_roles_disclosed' for f in findings)

def test_role_presentation():
    findings = run_module(js_content='role:"presentation"')
    assert not any(f['rule_id'] == 'js_auth_roles_disclosed' for f in findings)

def test_role_checkbox():
    findings = run_module(js_content='role:"checkbox"')
    assert not any(f['rule_id'] == 'js_auth_roles_disclosed' for f in findings)

def test_role_tabpanel():
    findings = run_module(js_content='role:"tabpanel"')
    assert not any(f['rule_id'] == 'js_auth_roles_disclosed' for f in findings)

def test_role_treeitem():
    findings = run_module(js_content='role:"treeitem"')
    assert not any(f['rule_id'] == 'js_auth_roles_disclosed' for f in findings)

# VALID SINGULAR ROLES
def test_role_admin():
    findings = run_module(js_content='role:"admin"')
    assert any(f['rule_id'] == 'js_auth_roles_disclosed' for f in findings)

def test_role_owner():
    findings = run_module(js_content='role:"owner"')
    assert any(f['rule_id'] == 'js_auth_roles_disclosed' for f in findings)

def test_role_user():
    findings = run_module(js_content='role:"user"')
    assert any(f['rule_id'] == 'js_auth_roles_disclosed' for f in findings)

def test_role_superadmin():
    findings = run_module(js_content='role:"superadmin"')
    assert any(f['rule_id'] == 'js_auth_roles_disclosed' for f in findings)

# EXISTING ARRAY / PERMISSION BEHAVIOR
def test_roles_array():
    findings = run_module(js_content='roles:["admin","viewer"]')
    assert any(f['rule_id'] == 'js_auth_roles_disclosed' for f in findings)

def test_permission_singular():
    findings = run_module(js_content='permission:"read"')
    assert any(f['rule_id'] == 'js_auth_roles_disclosed' for f in findings)

def test_permission_singular_dotted():
    findings = run_module(js_content='permission:"users.read"')
    assert not any(f['rule_id'] == 'js_auth_roles_disclosed' for f in findings)

def test_permissions_array():
    findings = run_module(js_content='permissions:["users.read"]')
    assert any(f['rule_id'] == 'js_auth_roles_disclosed' for f in findings)

# EDGE CASES / SCOPE PROTECTION
def test_userRole_admin():
    findings = run_module(js_content='userRole:"admin"')
    assert any(f['rule_id'] == 'js_auth_roles_disclosed' for f in findings)

def test_allowedRoles_admin():
    findings = run_module(js_content='allowedRoles:["admin"]')
    assert any(f['rule_id'] == 'js_auth_roles_disclosed' for f in findings)
