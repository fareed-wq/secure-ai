import pytest
import os
import re

def test_history_search_ui_access():
    ui_path = os.path.join('src', 'pages', 'ScanHistory.jsx')
    with open(ui_path, 'r', encoding='utf-8') as f:
        content = f.read()
    assert 'setSearchInput(e.target.value)' in content
    search_block = content[content.find('Search history by target')-200 : content.find('Search history by target')+200]
    assert 'isAdmin' not in search_block

def test_compare_entitlement_unchanged():
    ui_path = os.path.join('src', 'pages', 'ScanHistory.jsx')
    with open(ui_path, 'r', encoding='utf-8') as f:
        content = f.read()
    assert re.search(r'\{isAdmin\s*&&\s*\(\s*<button[^>]*onClick=\{handleCompare\}', content)
    assert re.search(r'\{isAdmin\s*&&\s*\(\s*<input[^>]*type="checkbox"', content)

def test_guest_cannot_access_history():
    from api.auth.entitlements import Entitlements
    ent = Entitlements({'sub': None})
    assert ent.can_view_scan_history == False

def test_search_uses_filtered_scans():
    ui_path = os.path.join('src', 'pages', 'ScanHistory.jsx')
    with open(ui_path, 'r', encoding='utf-8') as f:
        content = f.read()
    assert '{filteredScans.map((scan)' in content or '{filteredScans.map(scan' in content

def test_history_fetches_only_owned_scans():
    ui_path = os.path.join('src', 'pages', 'ScanHistory.jsx')
    with open(ui_path, 'r', encoding='utf-8') as f:
        content = f.read()
    assert ".eq('user_id', user.id)" in content

def test_auth_context_uses_rpc():
    ui_path = os.path.join('src', 'contexts', 'AuthContext.jsx')
    with open(ui_path, 'r', encoding='utf-8') as f:
        content = f.read()
    assert "supabase.rpc('is_admin')" in content
    assert "/api/admin/me" not in content

def test_admin_layout_verifies_backend():
    import api.auth.entitlements as ent
    with open(ent.__file__, 'r', encoding='utf-8') as f:
        content = f.read()
    assert "def require_admin" in content

def test_search_logic_implements_requirements():
    ui_path = os.path.join('src', 'pages', 'ScanHistory.jsx')
    with open(ui_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # partial/full target search
    assert "targetUrl.includes(term)" in content
    # type search (basic / advanced)
    assert "typeLabel.includes(term)" in content
    assert "getScanModeLabel" in content

    # clear search restores full history
    assert "setSearchInput('')" in content or 'setSearchInput("");' in content
    assert "setSearchTerm('')" in content or 'setSearchTerm("");' in content

    # debounce
    assert "setTimeout(() => {" in content
    assert "300" in content
