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
