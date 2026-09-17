import pytest
from unittest.mock import patch
from api.scanner.core import ModuleExecutionState
from api.scanner.orchestrator import scan_url

class MockReturnedModule:
    module_name = 'MockReturned'
    timeout = 10
    def run(self, url, hostname, session):
        return [{'name': 'Finding A', 'severity': 'Low'}]

class MockEmptyModule:
    module_name = 'MockEmpty'
    timeout = 10
    def run(self, url, hostname, session):
        return []

class MockFailedModule:
    module_name = 'MockFailed'
    timeout = 10
    def run(self, url, hostname, session):
        raise ValueError('Fatal crash')

class MockTimeoutModule:
    module_name = 'MockTimeout'
    timeout = 0.1
    def run(self, url, hostname, session):
        raise TimeoutError('connection timed out')

@pytest.fixture
def mock_modules():
    return [
        MockReturnedModule(),
        MockEmptyModule(),
        MockFailedModule(),
        MockTimeoutModule()
    ]

@patch('api.scanner.orchestrator.is_public_hostname', return_value=True)
@patch('api.scanner.orchestrator.check_liveness', return_value=True)
def test_phase1b1_execution_telemetry(mock_live, mock_pub, mock_modules, monkeypatch):
    import api.scanner.orchestrator
    monkeypatch.setattr(api.scanner.orchestrator, 'ACTIVE_MODULES', mock_modules)
    monkeypatch.setattr(api.scanner.orchestrator, 'PASSIVE_MODULES', [])

    result = scan_url('https://example.com', scan_mode='active')

    exec_data = result.get('module_execution', {})

    assert len(exec_data) == 4

    assert exec_data['MockReturned']['status'] == ModuleExecutionState.RETURNED
    assert exec_data['MockEmpty']['status'] == ModuleExecutionState.RETURNED

    assert exec_data['MockFailed']['status'] == ModuleExecutionState.FAILED
    assert exec_data['MockFailed'].get('reason') == 'module_exception'

    assert exec_data['MockTimeout']['status'] == ModuleExecutionState.TIMED_OUT
    assert exec_data['MockTimeout'].get('reason') == 'timeout_exception'

    findings = result.get('findings', [])
    err_findings = [f for f in findings if f.get('name') == 'Module Timeout / Error: MockFailed']
    assert len(err_findings) == 1
    assert 'Fatal crash' in err_findings[0]['evidence']['raw']

    timeout_findings = [f for f in findings if f.get('name') == 'Module Timeout / Error: MockTimeout']
    assert len(timeout_findings) == 1

def test_phase1b1_historical_compatibility():
    from api.scanner.scoring import calculate_score
    res = calculate_score('https://example.com', [], {}, None, completed_modules=1)
    assert 'module_execution' not in res

def test_phase1b1_global_budget(monkeypatch):
    import api.scanner.orchestrator

    class MockSuperSlow:
        module_name = 'MockSuperSlow'
        timeout = 10
        def run(self, url, hostname, session):
            import time
            time.sleep(1)
            return []

    monkeypatch.setattr(api.scanner.orchestrator, 'ACTIVE_MODULES', [MockSuperSlow()])
    monkeypatch.setattr(api.scanner.orchestrator, 'PASSIVE_MODULES', [])

    import time
    original_monotonic = time.monotonic
    def mock_monotonic():
        return original_monotonic() + 50

    monkeypatch.setattr(time, 'monotonic', mock_monotonic)

    # We also have to monkeypatch time.monotonic inside the local scope if it's imported locally?
    # Actually, scan_url imports time locally: `import time as _time`. It uses `_time.monotonic()`.
    # It's hard to patch a local import. Alternatively, patch SCAN_BUDGET_SECONDS globally?
    # But SCAN_BUDGET_SECONDS is defined inside the function.
    # What if we just patch the ThreadPoolExecutor?
    # No, the easiest is to just patch the timeout parameter in as_completed?
    # Actually, instead of all this, we can patch `getattr`? No.
    # Wait, `SCAN_BUDGET_SECONDS` is just a variable. How about we just sleep inside the module for longer than the global budget? But the budget is 45s, tests shouldn't wait 45s.

    # What if we patch `as_completed` directly?
    def mock_as_completed(futures, timeout=None):
        raise concurrent.futures.TimeoutError("Global timeout")

    import concurrent.futures
    monkeypatch.setattr(api.scanner.orchestrator, 'as_completed', mock_as_completed)

    monkeypatch.setattr(api.scanner.orchestrator, 'is_public_hostname', lambda x: True)
    monkeypatch.setattr(api.scanner.orchestrator, 'check_liveness', lambda x: True)

    res = api.scanner.orchestrator.scan_url('https://example.com', scan_mode='active')
    exec_data = res.get('module_execution', {})

    assert exec_data['MockSuperSlow']['status'] == ModuleExecutionState.NOT_COMPLETED
    assert exec_data['MockSuperSlow'].get('reason') == 'global_budget_exhausted'
