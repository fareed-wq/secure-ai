import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import os

from api.index import app
from api.admin import require_admin
from api.scanner.compare import compare_reports

client = TestClient(app)

def test_compare_reports_logic():
    old_scan = {
        "target_url": "https://example.com",
        "score": 80,
        "report_data": {
            "scan_mode": "passive",
            "findings": [
                {"name": "Missing Headers", "severity": "Medium", "evidence": "old"},
                {"name": "No CSP", "severity": "Low", "evidence": "old"},
                {"name": "Outdated TLS", "severity": "High"}
            ]
        }
    }
    new_scan = {
        "target_url": "https://example.com",
        "score": 90,
        "report_data": {
            "scan_mode": "passive",
            "findings": [
                {"name": "Missing Headers", "severity": "Medium", "evidence": "new"},
                {"name": "No CSP", "severity": "Info", "evidence": "new"}, # Improved!
                {"name": "Outdated TLS", "severity": "Critical"}, # Regressed!
                {"name": "New Issue", "severity": "High", "evidence": "new"}
            ]
        }
    }

    result = compare_reports(old_scan, new_scan)
    assert result["old_score"] == 80
    assert result["new_score"] == 90
    assert result["score_change"] == 10

    assert len(result["improved"]) == 1
    assert result["improved"][0]["name"] == "No CSP"

    assert len(result["regressed"]) == 1
    assert result["regressed"][0]["name"] == "Outdated TLS"

    assert len(result["added"]) == 1
    assert result["added"][0]["name"] == "New Issue"

    assert len(result["removed"]) == 0

    assert len(result["unchanged"]) == 1
    assert result["unchanged"][0]["name"] == "Missing Headers"


def test_compare_reports_different_targets():
    old_scan = {"target_url": "https://example.com"}
    new_scan = {"target_url": "https://other.com"}
    with pytest.raises(ValueError, match="Cannot compare scans with different target URLs."):
        compare_reports(old_scan, new_scan)

def test_compare_reports_different_modes():
    old_scan = {"target_url": "https://example.com", "report_data": {"scan_mode": "passive"}}
    new_scan = {"target_url": "https://example.com", "report_data": {"scan_mode": "active"}}
    with pytest.raises(ValueError, match="Cannot compare scans with different scan modes."):
        compare_reports(old_scan, new_scan)

def test_compare_reports_unknown_mode():
    old_scan = {"target_url": "https://example.com", "report_data": {"scan_mode": "unknown_string"}}
    new_scan = {"target_url": "https://example.com", "report_data": {"scan_mode": "unknown_string"}}
    with pytest.raises(ValueError, match="Cannot compare scans with unknown scan modes."):
        compare_reports(old_scan, new_scan)

@patch.dict(os.environ, {"SUPABASE_URL": "http://mock", "SUPABASE_SECRET_KEY": "mock"})
@patch("api.admin.requests.get")
def test_admin_compare_endpoint(mock_requests_get):
    app.dependency_overrides[require_admin] = lambda: {"sub": "admin123", "role": "admin"}

    # Mock supabase responses
    def mock_get(url, *args, **kwargs):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        if "id=eq.1" in url:
            mock_resp.json.return_value = [{
                "target_url": "https://example.com",
                "user_id": "admin123",
                "score": 80,
                "report_data": {"scan_mode": "passive", "findings": []}
            }]
        elif "id=eq.2" in url:
            mock_resp.json.return_value = [{
                "target_url": "https://example.com",
                "user_id": "admin123",
                "score": 90,
                "report_data": {"scan_mode": "passive", "findings": []}
            }]
        return mock_resp

    mock_requests_get.side_effect = mock_get

    try:
        response = client.get("/api/admin/scans/compare?scan_id_1=1&scan_id_2=2", headers={"Authorization": "Bearer token"})
        assert response.status_code == 200
        data = response.json()
        assert data["old_score"] == 80
        assert data["new_score"] == 90
        assert data["score_change"] == 10
    finally:
        app.dependency_overrides.clear()

def test_compare_reports_score_increase_only():
    old_scan = {
        "target_url": "https://example.com",
        "score": 80,
        "report_data": {
            "scan_mode": "passive",
            "findings": [
                {"name": "Issue", "severity": "Medium"}
            ]
        }
    }
    new_scan = {
        "target_url": "https://example.com",
        "score": 90,
        "report_data": {
            "scan_mode": "passive",
            "findings": [
                {"name": "Issue", "severity": "Medium"}
            ]
        }
    }

    from api.scanner.compare import compare_reports
    result = compare_reports(old_scan, new_scan)
    assert result["old_score"] == 80
    assert result["new_score"] == 90
    assert result["score_change"] == 10

    assert len(result["improved"]) == 0
    assert len(result["regressed"]) == 0
    assert len(result["added"]) == 0
    assert len(result["removed"]) == 0
    assert len(result["unchanged"]) == 1

def test_compare_reports_qa_improvement():
    old_scan = {
        "target_url": "https://qa.example.com",
        "score": 80,
        "report_data": {
            "scan_mode": "passive",
            "findings": [{"name": "Header Issue", "severity": "High"}]
        }
    }
    new_scan = {
        "target_url": "https://qa.example.com",
        "score": 90,
        "report_data": {
            "scan_mode": "passive",
            "findings": [{"name": "Header Issue", "severity": "Info"}]
        }
    }
    result = compare_reports(old_scan, new_scan)
    assert result["score_change"] == 10
    assert len(result["improved"]) == 1
    assert result["improved"][0]["name"] == "Header Issue"
    assert len(result["added"]) == 0
    assert len(result["removed"]) == 0

def test_compare_reports_qa_regression():
    old_scan = {
        "target_url": "https://qa.example.com",
        "score": 90,
        "report_data": {
            "scan_mode": "passive",
            "findings": [{"name": "Header Issue", "severity": "Info"}]
        }
    }
    new_scan = {
        "target_url": "https://qa.example.com",
        "score": 80,
        "report_data": {
            "scan_mode": "passive",
            "findings": [{"name": "Header Issue", "severity": "High"}]
        }
    }
    result = compare_reports(old_scan, new_scan)
    assert result["score_change"] == -10
    assert len(result["regressed"]) == 1
    assert result["regressed"][0]["name"] == "Header Issue"
    assert len(result["added"]) == 0
    assert len(result["removed"]) == 0

def test_compare_reports_qa_added():
    old_scan = {
        "target_url": "https://qa.example.com",
        "score": 90,
        "report_data": {
            "scan_mode": "passive",
            "findings": []
        }
    }
    new_scan = {
        "target_url": "https://qa.example.com",
        "score": 80,
        "report_data": {
            "scan_mode": "passive",
            "findings": [{"name": "New Finding", "severity": "High"}]
        }
    }
    result = compare_reports(old_scan, new_scan)
    assert len(result["added"]) == 1
    assert result["added"][0]["name"] == "New Finding"
    assert len(result["removed"]) == 0
    assert len(result["improved"]) == 0
    assert len(result["regressed"]) == 0

def test_compare_reports_qa_removed():
    old_scan = {
        "target_url": "https://qa.example.com",
        "score": 80,
        "report_data": {
            "scan_mode": "passive",
            "findings": [{"name": "Old Finding", "severity": "High"}]
        }
    }
    new_scan = {
        "target_url": "https://qa.example.com",
        "score": 90,
        "report_data": {
            "scan_mode": "passive",
            "findings": []
        }
    }
    result = compare_reports(old_scan, new_scan)
    assert len(result["removed"]) == 1
    assert result["removed"][0]["name"] == "Old Finding"
    assert len(result["added"]) == 0
    assert len(result["improved"]) == 0
    assert len(result["regressed"]) == 0

def test_compare_reports_qa_unchanged():
    old_scan = {
        "target_url": "https://qa.example.com",
        "score": 80,
        "report_data": {
            "scan_mode": "passive",
            "findings": [{"name": "Same Finding", "severity": "High"}]
        }
    }
    new_scan = {
        "target_url": "https://qa.example.com",
        "score": 80,
        "report_data": {
            "scan_mode": "passive",
            "findings": [{"name": "Same Finding", "severity": "High"}]
        }
    }
    result = compare_reports(old_scan, new_scan)
    assert len(result["unchanged"]) == 1
    assert result["unchanged"][0]["name"] == "Same Finding"
    assert len(result["added"]) == 0
    assert len(result["removed"]) == 0
    assert len(result["improved"]) == 0
    assert len(result["regressed"]) == 0

def test_compare_reports_qa_mixed():
    old_scan = {
        "target_url": "https://qa.example.com",
        "score": 80,
        "report_data": {
            "scan_mode": "passive",
            "findings": [
                {"name": "Improved Finding", "severity": "High"},
                {"name": "Regressed Finding", "severity": "Info"},
                {"name": "Removed Finding", "severity": "Medium"},
                {"name": "Unchanged Finding", "severity": "Low"}
            ]
        }
    }
    new_scan = {
        "target_url": "https://qa.example.com",
        "score": 80,
        "report_data": {
            "scan_mode": "passive",
            "findings": [
                {"name": "Improved Finding", "severity": "Info"},
                {"name": "Regressed Finding", "severity": "Critical"},
                {"name": "Added Finding", "severity": "Medium"},
                {"name": "Unchanged Finding", "severity": "Low"}
            ]
        }
    }
    result = compare_reports(old_scan, new_scan)
    assert len(result["improved"]) == 1
    assert result["improved"][0]["name"] == "Improved Finding"

    assert len(result["regressed"]) == 1
    assert result["regressed"][0]["name"] == "Regressed Finding"

    assert len(result["added"]) == 1
    assert result["added"][0]["name"] == "Added Finding"

    assert len(result["removed"]) == 1
    assert result["removed"][0]["name"] == "Removed Finding"

    assert len(result["unchanged"]) == 1
    assert result["unchanged"][0]["name"] == "Unchanged Finding"

import pytest
from fastapi.testclient import TestClient
from api.index import app, get_current_user

def test_history_compare_endpoint_owner(monkeypatch):
    monkeypatch.setenv("SUPABASE_URL", "http://mock")
    monkeypatch.setenv("SUPABASE_SECRET_KEY", "mock")
    monkeypatch.setattr("api.auth.entitlements.SUPABASE_URL", "http://mock")
    monkeypatch.setattr("api.auth.entitlements.SUPABASE_SECRET_KEY", "mock")
    app.dependency_overrides[get_current_user] = lambda: {"sub": "user-123"}
    client = TestClient(app)

    scan1_data = {
        "id": "scan-1",
        "target_url": "https://example.com",
        "user_id": "user-123",
        "report_data": {"scan_mode": "basic", "score": 80, "findings": []}
    }
    scan2_data = {
        "id": "scan-2",
        "target_url": "https://example.com",
        "user_id": "user-123",
        "report_data": {"scan_mode": "basic", "score": 90, "findings": []}
    }

    # Entitlements requires professional for non-admin to compare
    def mock_get(*args, **kwargs):
        class MockResp:
            status_code = 200
            def json(self):
                url = args[0]
                if "user_roles" in url:
                    return [{"role": "free"}]
                if "user_plans" in url:
                    return [{"plan": "professional", "status": "active"}]
                if "scan-1" in url and "user-123" in url:
                    return [scan1_data]
                if "scan-2" in url and "user-123" in url:
                    return [scan2_data]
                return []
        return MockResp()

    monkeypatch.setattr("requests.get", mock_get)

    resp = client.get("/api/scans/compare?scan_id_1=scan-1&scan_id_2=scan-2")
    assert resp.status_code == 200
    assert resp.json()["score_change"] == 10

    app.dependency_overrides = {}

def test_history_compare_endpoint_non_owner(monkeypatch):
    monkeypatch.setenv("SUPABASE_URL", "http://mock")
    monkeypatch.setenv("SUPABASE_SECRET_KEY", "mock")
    monkeypatch.setattr("api.auth.entitlements.SUPABASE_URL", "http://mock")
    monkeypatch.setattr("api.auth.entitlements.SUPABASE_SECRET_KEY", "mock")
    app.dependency_overrides[get_current_user] = lambda: {"sub": "user-hacker"}
    client = TestClient(app)

    def mock_get(*args, **kwargs):
        class MockResp:
            status_code = 200
            def json(self):
                url = args[0]
                if "user_roles" in url:
                    return [{"role": "free"}]
                if "user_plans" in url:
                    return [{"plan": "professional", "status": "active"}]
                return []
        return MockResp()
    monkeypatch.setattr("requests.get", mock_get)

    resp = client.get("/api/scans/compare?scan_id_1=scan-1&scan_id_2=scan-2")
    assert resp.status_code == 404

    app.dependency_overrides = {}

def test_history_compare_endpoint_free_blocked(monkeypatch):
    monkeypatch.setenv("SUPABASE_URL", "http://mock")
    monkeypatch.setenv("SUPABASE_SECRET_KEY", "mock")
    monkeypatch.setattr("api.auth.entitlements.SUPABASE_URL", "http://mock")
    monkeypatch.setattr("api.auth.entitlements.SUPABASE_SECRET_KEY", "mock")
    app.dependency_overrides[get_current_user] = lambda: {"sub": "user-free"}
    client = TestClient(app)

    def mock_get(*args, **kwargs):
        class MockResp:
            status_code = 200
            def json(self):
                url = args[0]
                if "user_roles" in url:
                    return [{"role": "free"}]
                if "user_plans" in url:
                    return [{"plan": "free", "status": "active"}]
                return []
        return MockResp()
    monkeypatch.setattr("requests.get", mock_get)

    resp = client.get("/api/scans/compare?scan_id_1=scan-1&scan_id_2=scan-2")
    assert resp.status_code == 403
    assert "Professional" in resp.json()["error"]

    app.dependency_overrides = {}

def test_admin_compare_scans_owner(monkeypatch):
    from api.admin import require_admin
    monkeypatch.setenv("SUPABASE_URL", "http://mock")
    monkeypatch.setenv("SUPABASE_SECRET_KEY", "mock")
    app.dependency_overrides[require_admin] = lambda: {"sub": "admin-123"}
    client = TestClient(app)

    scan1_data = {
        "id": "scan-1",
        "target_url": "https://example.com",
        "user_id": "admin-123",
        "report_data": {"scan_mode": "basic", "score": 80, "findings": []}
    }
    scan2_data = {
        "id": "scan-2",
        "target_url": "https://example.com",
        "user_id": "admin-123",
        "report_data": {"scan_mode": "basic", "score": 90, "findings": []}
    }

    def mock_get(*args, **kwargs):
        class MockResp:
            status_code = 200
            def json(self):
                url = args[0]
                if "scan-1" in url:
                    return [scan1_data]
                if "scan-2" in url:
                    return [scan2_data]
                return []
        return MockResp()

    monkeypatch.setattr("requests.get", mock_get)

    resp = client.get("/api/admin/scans/compare?scan_id_1=scan-1&scan_id_2=scan-2")
    assert resp.status_code == 200

    app.dependency_overrides.clear()

def test_admin_compare_scans_other_user(monkeypatch):
    from api.admin import require_admin
    monkeypatch.setenv("SUPABASE_URL", "http://mock")
    monkeypatch.setenv("SUPABASE_SECRET_KEY", "mock")
    app.dependency_overrides[require_admin] = lambda: {"sub": "admin-123"}
    client = TestClient(app)

    scan1_data = {
        "id": "scan-1",
        "target_url": "https://example.com",
        "user_id": "admin-123",
        "report_data": {"scan_mode": "basic", "score": 80, "findings": []}
    }
    scan2_data = {
        "id": "scan-2",
        "target_url": "https://example.com",
        "user_id": "other-user-456",
        "report_data": {"scan_mode": "basic", "score": 90, "findings": []}
    }

    def mock_get(*args, **kwargs):
        class MockResp:
            status_code = 200
            def json(self):
                url = args[0]
                if "scan-1" in url:
                    return [scan1_data]
                if "scan-2" in url:
                    return [scan2_data]
                return []
        return MockResp()

    monkeypatch.setattr("requests.get", mock_get)

    resp = client.get("/api/admin/scans/compare?scan_id_1=scan-1&scan_id_2=scan-2")
    assert resp.status_code == 403

    app.dependency_overrides.clear()

# === NEW PHASE 1 REGRESSION TESTS ===

def test_compare_duplicate_not_discarded():
    old = {
        "target_url": "https://example.com",
        "report_data": {
            "scan_mode": "basic",
            "findings": [
                {"name": "Duplicate Name", "module": "modA", "severity": "Medium"},
                {"name": "Duplicate Name", "module": "modA", "severity": "High"}
            ]
        }
    }
    new = {
        "target_url": "https://example.com",
        "report_data": {
            "scan_mode": "basic",
            "findings": [
                {"name": "Duplicate Name", "module": "modA", "severity": "Medium"},
                {"name": "Duplicate Name", "module": "modA", "severity": "High"}
            ]
        }
    }
    res = compare_reports(old, new)
    assert len(res["unchanged"]) == 2

def test_compare_duplicate_removed():
    old = {
        "target_url": "https://example.com",
        "report_data": {
            "scan_mode": "basic",
            "findings": [
                {"name": "Duplicate Name", "module": "modA", "severity": "Medium"},
                {"name": "Duplicate Name", "module": "modA", "severity": "Medium"}
            ]
        }
    }
    new = {
        "target_url": "https://example.com",
        "report_data": {
            "scan_mode": "basic",
            "findings": [
                {"name": "Duplicate Name", "module": "modA", "severity": "Medium"}
            ]
        }
    }
    res = compare_reports(old, new)
    assert len(res["unchanged"]) == 1
    assert len(res["removed"]) == 1

def test_compare_duplicate_added():
    old = {
        "target_url": "https://example.com",
        "report_data": {
            "scan_mode": "basic",
            "findings": [
                {"name": "Duplicate Name", "module": "modA", "severity": "Medium"}
            ]
        }
    }
    new = {
        "target_url": "https://example.com",
        "report_data": {
            "scan_mode": "basic",
            "findings": [
                {"name": "Duplicate Name", "module": "modA", "severity": "Medium"},
                {"name": "Duplicate Name", "module": "modA", "severity": "Medium"}
            ]
        }
    }
    res = compare_reports(old, new)
    assert len(res["unchanged"]) == 1
    assert len(res["added"]) == 1

def test_compare_exact_severity_pairing_first():
    old = {
        "target_url": "https://example.com",
        "report_data": {
            "scan_mode": "basic",
            "findings": [
                {"name": "Test", "module": "mod", "severity": "Medium"},
                {"name": "Test", "module": "mod", "severity": "High"}
            ]
        }
    }
    new = {
        "target_url": "https://example.com",
        "report_data": {
            "scan_mode": "basic",
            "findings": [
                {"name": "Test", "module": "mod", "severity": "Medium"},
                {"name": "Test", "module": "mod", "severity": "Critical"}
            ]
        }
    }
    res = compare_reports(old, new)
    # Medium matches Medium (unchanged)
    # High -> Critical (regressed)
    assert len(res["unchanged"]) == 1
    assert res["unchanged"][0]["severity"] == "Medium"
    assert len(res["regressed"]) == 1
    assert res["regressed"][0]["old"]["severity"] == "High"
    assert res["regressed"][0]["new"]["severity"] == "Critical"

def test_compare_same_name_different_module():
    old = {
        "target_url": "https://example.com",
        "report_data": {
            "scan_mode": "basic",
            "findings": [
                {"name": "CommonName", "module": "ModuleA", "severity": "Low"}
            ]
        }
    }
    new = {
        "target_url": "https://example.com",
        "report_data": {
            "scan_mode": "basic",
            "findings": [
                {"name": "CommonName", "module": "ModuleB", "severity": "Low"}
            ]
        }
    }
    res = compare_reports(old, new)
    # Should not collide. Old is removed, new is added.
    assert len(res["unchanged"]) == 0
    assert len(res["removed"]) == 1
    assert res["removed"][0]["module"] == "ModuleA"
    assert len(res["added"]) == 1
    assert res["added"][0]["module"] == "ModuleB"

def test_compare_missing_module_legacy_fallback():
    old = {
        "target_url": "https://example.com",
        "report_data": {
            "scan_mode": "basic",
            "findings": [
                {"name": "LegacyName", "severity": "Medium"}
            ]
        }
    }
    new = {
        "target_url": "https://example.com",
        "report_data": {
            "scan_mode": "basic",
            "findings": [
                {"name": "LegacyName", "severity": "Medium"}
            ]
        }
    }
    res = compare_reports(old, new)
    assert len(res["unchanged"]) == 1

def test_compare_conservation():
    old = {
        "target_url": "https://example.com",
        "report_data": {
            "scan_mode": "basic",
            "findings": [
                {"name": "A", "module": "mod", "severity": "High"},
                {"name": "A", "module": "mod", "severity": "High"},
                {"name": "A", "module": "mod", "severity": "Medium"}
            ]
        }
    }
    new = {
        "target_url": "https://example.com",
        "report_data": {
            "scan_mode": "basic",
            "findings": [
                {"name": "A", "module": "mod", "severity": "High"},
                {"name": "A", "module": "mod", "severity": "Critical"},
                {"name": "A", "module": "mod", "severity": "Low"},
                {"name": "A", "module": "mod", "severity": "Low"}
            ]
        }
    }
    res = compare_reports(old, new)
    # OLD: 3 findings. NEW: 4 findings.
    # Total matched pairs + removed = 3 (size of OLD)
    # Total matched pairs + added = 4 (size of NEW)
    num_unchanged = len(res["unchanged"])
    num_improved = len(res["improved"])
    num_regressed = len(res["regressed"])
    num_added = len(res["added"])
    num_removed = len(res["removed"])

    total_matched_pairs = num_unchanged + num_improved + num_regressed
    assert total_matched_pairs + num_removed == 3
    assert total_matched_pairs + num_added == 4

# === NEW CROSS-VERSION MODULE FALLBACK TESTS ===

def test_compare_old_missing_module_new_has():
    old = {
        "target_url": "https://example.com",
        "report_data": {
            "scan_mode": "basic",
            "findings": [{"name": "X", "severity": "Medium"}]
        }
    }
    new = {
        "target_url": "https://example.com",
        "report_data": {
            "scan_mode": "basic",
            "findings": [{"name": "X", "module": "ModuleA", "severity": "Medium"}]
        }
    }
    res = compare_reports(old, new)
    assert len(res["unchanged"]) == 1
    assert len(res["added"]) == 0
    assert len(res["removed"]) == 0

def test_compare_old_has_module_new_missing():
    old = {
        "target_url": "https://example.com",
        "report_data": {
            "scan_mode": "basic",
            "findings": [{"name": "X", "module": "ModuleA", "severity": "Medium"}]
        }
    }
    new = {
        "target_url": "https://example.com",
        "report_data": {
            "scan_mode": "basic",
            "findings": [{"name": "X", "severity": "Medium"}]
        }
    }
    res = compare_reports(old, new)
    assert len(res["unchanged"]) == 1
    assert len(res["added"]) == 0
    assert len(res["removed"]) == 0

def test_compare_ambiguous_legacy_matching():
    old = {
        "target_url": "https://example.com",
        "report_data": {
            "scan_mode": "basic",
            "findings": [{"name": "X", "severity": "Medium"}]
        }
    }
    new = {
        "target_url": "https://example.com",
        "report_data": {
            "scan_mode": "basic",
            "findings": [
                {"name": "X", "module": "ModuleA", "severity": "Medium"},
                {"name": "X", "module": "ModuleB", "severity": "Medium"}
            ]
        }
    }
    res = compare_reports(old, new)
    # Ambiguous! Old X shouldn't map to either because it lacks module and there's 2 matches.
    # Total findings conserved: Old has 1, New has 2.
    assert len(res["unchanged"]) == 0
    assert len(res["removed"]) == 1
    assert len(res["added"]) == 2

def test_compare_duplicates_with_legacy_absence():
    old = {
        "target_url": "https://example.com",
        "report_data": {
            "scan_mode": "basic",
            "findings": [
                {"name": "X", "severity": "Medium"},
                {"name": "X", "severity": "High"}
            ]
        }
    }
    new = {
        "target_url": "https://example.com",
        "report_data": {
            "scan_mode": "basic",
            "findings": [
                {"name": "X", "module": "ModuleA", "severity": "Medium"},
                {"name": "X", "module": "ModuleA", "severity": "High"}
            ]
        }
    }
    res = compare_reports(old, new)
    # Unambiguous merge, both lists combined
    assert len(res["unchanged"]) == 2
    assert len(res["added"]) == 0
    assert len(res["removed"]) == 0
