import pytest
from unittest.mock import patch, MagicMock
from api.scanner.orchestrator import scan_url

@patch('api.scanner.orchestrator.check_liveness', return_value=True)
@patch('api.scanner.orchestrator.is_public_hostname', return_value=True)
@patch('api.scanner.orchestrator.safe_request')
@patch('api.scanner.orchestrator.ThreadPoolExecutor')
def test_scan_mode_selection(mock_pool, mock_req, mock_public, mock_liveness):
    # Mock pool to just capture the submitted modules
    submitted_modules = []
    
    def mock_submit(fn, *args, **kwargs):
        # the function submitted is usually `mod.run` where mod is the module instance
        if hasattr(fn, '__self__') and hasattr(fn.__self__, 'module_name'):
            submitted_modules.append(fn.__self__.__class__.__name__)
            class DummyListFuture:
                def result(self, timeout=None): return []
                def done(self): return True
                def cancel(self): pass
            return DummyListFuture()
        elif hasattr(fn, '__name__') and fn.__name__ == 'get_metadata':
            class DummyDictFuture:
                def result(self, timeout=None): return {}
                def done(self): return True
                def cancel(self): pass
            return DummyDictFuture()
            
        class DummyFuture:
            def result(self, timeout=None): return []
            def done(self): return True
            def cancel(self): pass
        return DummyFuture()
        
    # We must patch as_completed because it waits on futures
    with patch('api.scanner.orchestrator.as_completed', return_value=[]):
        mock_pool.return_value.submit.side_effect = mock_submit
        
        # Test 1 - Default passive mode
        submitted_modules.clear()
        scan_url("https://example.com")
        assert "ExposedFilesModule" not in submitted_modules
        assert "DNSCAAModule" not in submitted_modules
        assert "JavaScriptSecurityModule" not in submitted_modules
        assert "SubdomainProbingModule" not in submitted_modules
        assert "SubdomainTakeoverModule" not in submitted_modules
        assert "AuthenticationSessionSecurityModule" in submitted_modules

        # Test 2 - Explicit passive mode
        submitted_modules.clear()
        scan_url("https://example.com", scan_mode="passive")
        assert "ExposedFilesModule" not in submitted_modules
        assert "DNSCAAModule" not in submitted_modules
        assert "AuthenticationSessionSecurityModule" in submitted_modules

        # Test 3 - Passive mode cannot be bypassed
        submitted_modules.clear()
        scan_url("https://example.com", probe_subdomains=True, scan_mode="passive")
        assert "SubdomainProbingModule" not in submitted_modules
        assert "ExposedFilesModule" not in submitted_modules

        # Test 4 - Explicit active mode
        submitted_modules.clear()
        scan_url("https://example.com", scan_mode="active")
        assert "ExposedFilesModule" in submitted_modules
        assert "DNSCAAModule" in submitted_modules
        assert "AuthenticationSessionSecurityModule" in submitted_modules
        assert "SubdomainProbingModule" not in submitted_modules

        # Test 5 - Active + subdomain probing
        submitted_modules.clear()
        scan_url("https://example.com", scan_mode="active", probe_subdomains=True)
        assert "ExposedFilesModule" in submitted_modules
        assert "SubdomainProbingModule" in submitted_modules
        
        # Test 6 - Invalid scan mode
        res = scan_url("https://example.com", scan_mode="invalid_mode")
        assert res.get("status") == "failed"
        assert "Invalid scan_mode" in res.get("error", "")

        # Test 7 - Legacy takeover remains absent
        submitted_modules.clear()
        scan_url("https://example.com", scan_mode="active")
        assert "SubdomainTakeoverModule" not in submitted_modules

