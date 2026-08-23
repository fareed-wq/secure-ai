import pytest
import os
import re

def test_scanner_redirects_authenticated_users():
    ui_path = os.path.join('src', 'pages', 'Scanner.jsx')
    with open(ui_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    assert 'navigate(' in content and 'history' in content
    assert "setScanState('scanning')" in content
    assert "await scanApi.runScan" in content
    assert re.search(r'if\s*\(\s*user\s*&&\s*data\.id\s*\)\s*\{\s*navigate\(`/history/\$\{data\.id\}', content) is not None

def test_scanner_saves_guest_to_session_storage():
    ui_path = os.path.join('src', 'pages', 'Scanner.jsx')
    with open(ui_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    assert "sessionStorage.setItem('guestScanResult'" in content
    assert "sessionStorage.getItem('guestScanResult')" in content
    assert "setScanState('view-report')" in content

def test_scan_report_does_not_execute_scanner():
    ui_path = os.path.join('src', 'pages', 'ScanReport.jsx')
    with open(ui_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    assert 'scanApi.runScan' not in content
    assert 'fetchQuota' not in content
    assert ".from('scans')" in content
    assert ".eq('id', scanId)" in content
    assert 'animate-pulse' in content
    assert 'bg-slate-800' in content

def test_backend_returns_scan_id_for_auth_users():
    api_path = os.path.join('api', 'index.py')
    with open(api_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    assert 'result["id"] = db_res.json()[0].get("id")' in content
