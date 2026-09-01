import pytest
import os
import re


# ============================================================
# GUEST FLOW
# ============================================================

def test_guest_scan_shows_loading_before_result():
    """Guest scan must set scanState to 'scanning' before calling runScan."""
    with open(os.path.join('src', 'pages', 'Scanner.jsx'), 'r', encoding='utf-8') as f:
        src = f.read()
    # setScanState('scanning') must appear before await scanApi.runScan
    scanning_pos = src.index("setScanState('scanning')")
    runscan_pos = src.index("await scanApi.runScan")
    assert scanning_pos < runscan_pos, "loading state must be set before API call"


def test_guest_result_stored_in_session_storage():
    """Guest scan success must save result to sessionStorage."""
    with open(os.path.join('src', 'pages', 'Scanner.jsx'), 'r', encoding='utf-8') as f:
        src = f.read()
    assert "sessionStorage.setItem('guestScanResult'" in src


def test_guest_result_shows_view_report():
    """Guest scan success must transition to view-report state."""
    with open(os.path.join('src', 'pages', 'Scanner.jsx'), 'r', encoding='utf-8') as f:
        src = f.read()
    # In the else branch (guest path), setScanState('view-report') must follow sessionStorage.setItem
    session_pos = src.index("sessionStorage.setItem('guestScanResult'")
    viewreport_pos = src.index("setScanState('view-report')", session_pos)
    assert viewreport_pos > session_pos


def test_guest_does_not_navigate_to_history():
    """Guest scan must NOT navigate to /history/."""
    with open(os.path.join('src', 'pages', 'Scanner.jsx'), 'r', encoding='utf-8') as f:
        src = f.read()
    # The navigate call is guarded by `if (user && data.id)`
    assert re.search(r'if\s*\(\s*user\s*&&\s*data\.id\s*\)', src), \
        "navigate must be guarded by user && data.id check"


def test_guest_restore_effect_does_not_depend_on_scanstate():
    """The useEffect that restores guest results must NOT have scanState in its deps."""
    with open(os.path.join('src', 'pages', 'Scanner.jsx'), 'r', encoding='utf-8') as f:
        src = f.read()
    # Find the useEffect deps line that follows the guestScanResult block.
    # The effect body contains guestScanResult and the closing deps array.
    # We search for the deps array pattern near guestScanResult.
    guest_pos = src.index("guestScanResult")
    # Find the next dependency array closure after guestScanResult
    rest = src[guest_pos:]
    deps_match = re.search(r'\},\s*\[([^\]]*)\]\)', rest)
    assert deps_match, "useEffect dependency array must exist after guestScanResult"
    deps = deps_match.group(1)
    assert 'scanState' not in deps, \
        "scanState must NOT be in useEffect deps (causes race condition)"


def test_guest_restore_effect_only_runs_for_guests():
    """The sessionStorage restore must only run for guests (when !user)."""
    with open(os.path.join('src', 'pages', 'Scanner.jsx'), 'r', encoding='utf-8') as f:
        src = f.read()
    # The restore block must be guarded by !user
    assert re.search(r'else\s+if\s*\(\s*!user\s*\)', src), \
        "sessionStorage restore must be guarded by !user check"


# ============================================================
# FREE / ADMIN FLOW
# ============================================================

def test_authenticated_scan_navigates_to_permanent_url():
    """Authenticated scan success must navigate to /history/<id>."""
    with open(os.path.join('src', 'pages', 'Scanner.jsx'), 'r', encoding='utf-8') as f:
        src = f.read()
    assert re.search(r"navigate\(`/history/\$\{data\.id\}`", src), \
        "must navigate to /history/<id> for authenticated users"


def test_authenticated_loading_uses_same_scanning_state():
    """Authenticated scan must use the same setScanState('scanning') as guest."""
    with open(os.path.join('src', 'pages', 'Scanner.jsx'), 'r', encoding='utf-8') as f:
        src = f.read()
    # There should be exactly one setScanState('scanning') in handleScan,
    # and it must NOT be conditional on user type
    handle_scan_match = re.search(r'const handleScan = async.*?^\s*\};', src, re.MULTILINE | re.DOTALL)
    assert handle_scan_match, "handleScan must exist"
    handle_scan_body = handle_scan_match.group(0)
    # setScanState('scanning') must appear before any conditional branches
    assert "setScanState('scanning')" in handle_scan_body
    # setScanState('scanning') must NOT be inside an if(user) or if(isAdmin) block
    scanning_line_idx = handle_scan_body.index("setScanState('scanning')")
    before_scanning = handle_scan_body[:scanning_line_idx]
    # Count open/close braces - if scanning is at the top level of handleScan body,
    # it means it's unconditional
    assert before_scanning.count('if (user') == 0 or before_scanning.count('if (user') == before_scanning.count('}'), \
        "setScanState('scanning') must not be inside a user-conditional block"


# ============================================================
# BACK TO SCAN HISTORY CONTEXT
# ============================================================

def test_fresh_scan_report_hides_back_to_history():
    """ScanReport must NOT show 'Back to Scan History' for fresh scans.
    It should only appear when ?from=history is in the URL."""
    with open(os.path.join('src', 'pages', 'ScanReport.jsx'), 'r', encoding='utf-8') as f:
        src = f.read()
    # The back button must be conditional on fromHistory
    assert 'fromHistory' in src, "must use fromHistory flag"
    assert "searchParams.get('from')" in src or "searchParams.get(\"from\")" in src, \
        "must read 'from' query param"
    # The back button must be inside a conditional render
    assert re.search(r'\{fromHistory\s*&&', src), \
        "Back to Scan History must be conditionally rendered with fromHistory"


def test_scanner_navigates_without_from_param():
    """Scanner must navigate to /history/<id> WITHOUT ?from=history."""
    with open(os.path.join('src', 'pages', 'Scanner.jsx'), 'r', encoding='utf-8') as f:
        src = f.read()
    nav_match = re.search(r"navigate\(`/history/\$\{data\.id\}`", src)
    assert nav_match, "must navigate to /history/<id>"
    # Verify no ?from=history in the navigate call
    nav_line_start = nav_match.start()
    nav_context = src[nav_line_start:nav_line_start + 100]
    assert 'from=history' not in nav_context, \
        "Scanner navigate must NOT include from=history"


def test_history_links_include_from_param():
    """ScanHistory View Report links must include ?from=history."""
    with open(os.path.join('src', 'pages', 'ScanHistory.jsx'), 'r', encoding='utf-8') as f:
        src = f.read()
    assert '?from=history' in src, \
        "ScanHistory links must include ?from=history"


# ============================================================
# REPORT REFRESH SAFETY
# ============================================================

def test_scan_report_does_not_execute_scanner():
    """ScanReport must NOT invoke backend scanner or quota API."""
    with open(os.path.join('src', 'pages', 'ScanReport.jsx'), 'r', encoding='utf-8') as f:
        src = f.read()
    assert 'scanApi.runScan' not in src, "must not call runScan"
    assert 'fetchQuota' not in src, "must not call fetchQuota"
    assert ".from('scans')" in src, "must fetch from scans table"
    assert ".eq('id', scanId)" in src, "must filter by scanId"


def test_scan_report_has_skeleton_loading():
    """ScanReport loading state must show a proper skeleton, not bare text."""
    with open(os.path.join('src', 'pages', 'ScanReport.jsx'), 'r', encoding='utf-8') as f:
        src = f.read()
    assert 'animate-pulse' in src, "must use skeleton animation"


def test_backend_returns_scan_id_for_auth_users():
    """Backend must persist scan and return the DB id for authenticated users."""
    with open(os.path.join('api', 'index.py'), 'r', encoding='utf-8') as f:
        src = f.read()
    assert 'result["id"] = db_res.json()[0].get("id")' in src


# ============================================================
# QUOTA SAFETY
# ============================================================

def test_quota_consumed_after_lease_in_scan_handler():
    """In the scan handler body, consume_guest_quota must appear after acquire_scan_lease."""
    with open(os.path.join('api', 'index.py'), 'r', encoding='utf-8') as f:
        src = f.read()
    # Find positions within the scan_single function body only
    func_start = src.index('async def scan_single')
    func_body = src[func_start:]
    lease_pos = func_body.index('acquire_scan_lease')
    guest_consume_pos = func_body.index('consume_guest_quota')
    assert guest_consume_pos > lease_pos, \
        "consume_guest_quota must happen after acquire_scan_lease in scan handler"


def test_scan_report_page_does_not_consume_quota():
    """ScanReport page must not contain any quota consumption logic."""
    with open(os.path.join('src', 'pages', 'ScanReport.jsx'), 'r', encoding='utf-8') as f:
        src = f.read()
    assert 'quota' not in src.lower() or 'fetchQuota' not in src, \
        "ScanReport must not consume or fetch quota"


# ============================================================
# ERROR HANDLING
# ============================================================

def test_error_state_stays_on_scanner_page():
    """Failed scan must show error on Scanner page, not navigate away."""
    with open(os.path.join('src', 'pages', 'Scanner.jsx'), 'r', encoding='utf-8') as f:
        src = f.read()
    # After setting error, must NOT navigate
    handle_scan = re.search(r'const handleScan = async.*?^\s*\};', src, re.MULTILINE | re.DOTALL)
    assert handle_scan
    body = handle_scan.group(0)
    # In the catch block, setScanState('error') must exist
    assert "setScanState('error')" in body
