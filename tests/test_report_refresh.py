import pytest
import os

def test_scanner_redirects_authenticated_users():
    ui_path = os.path.join('src', 'pages', 'Scanner.jsx')
    with open(ui_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Must redirect to history route using the saved ID
    assert 'navigate(' in content and 'history' in content

def test_scanner_saves_guest_to_session_storage():
    ui_path = os.path.join('src', 'pages', 'Scanner.jsx')
    with open(ui_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Guest must use sessionStorage
    assert "sessionStorage.setItem('guestScanResult'" in content
    assert "sessionStorage.getItem('guestScanResult')" in content

def test_scan_report_does_not_execute_scanner():
    ui_path = os.path.join('src', 'pages', 'ScanReport.jsx')
    with open(ui_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Must not invoke the backend scanner or quota
    assert 'scanApi.runScan' not in content
    assert 'fetchQuota' not in content
    
    # Must only fetch the report from the DB
    assert ".from('scans')" in content
    assert ".eq('id', scanId)" in content

def test_backend_returns_scan_id_for_auth_users():
    api_path = os.path.join('api', 'index.py')
    with open(api_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Backend must persist the scan and set result["id"]
    assert 'result["id"] = db_res.json()[0].get("id")' in content
