import pytest
from unittest.mock import patch
from api.scanner.core import AssessmentOutcome, ModuleResult, ModuleExecutionState
from api.scanner.orchestrator import scan_url
import requests

class LegacyListModule:
    module_name = 'LegacyList'
    timeout = 10
    def run(self, url, hostname, session):
        return [{'name': 'Finding', 'severity': 'Low'}]

class CompletedModule:
    module_name = 'CompletedMod'
    timeout = 10
    def run(self, url, hostname, session):
        return ModuleResult([{'name': 'Finding', 'severity': 'Low'}], AssessmentOutcome.COMPLETED)

class PartialModule:
    module_name = 'PartialMod'
    timeout = 10
    def run(self, url, hostname, session):
        return ModuleResult([], AssessmentOutcome.PARTIAL)

class NotApplicableModule:
    module_name = 'NAMod'
    timeout = 10
    def run(self, url, hostname, session):
        return ModuleResult([], AssessmentOutcome.NOT_APPLICABLE)

class BlockedModule:
    module_name = 'BlockedMod'
    timeout = 10
    def run(self, url, hostname, session):
        return ModuleResult([], AssessmentOutcome.BLOCKED)

class FailedModule:
    module_name = 'FailedMod'
    timeout = 10
    def run(self, url, hostname, session):
        raise ValueError('crash')

class TimeoutModule:
    module_name = 'TimeoutMod'
    timeout = 0.1
    def run(self, url, hostname, session):
        raise requests.exceptions.Timeout('timeout')

@pytest.fixture
def override_modules():
    mods = [
        LegacyListModule(), CompletedModule(), PartialModule(),
        NotApplicableModule(), BlockedModule(), FailedModule(), TimeoutModule()
    ]
    with patch('api.scanner.orchestrator.ACTIVE_MODULES', mods),          patch('api.scanner.orchestrator.PASSIVE_MODULES', []):
        yield

def test_phase1b2_execution_and_assessment(override_modules):
    res = scan_url('https://example.com', scan_mode='active')
    exec_data = res.get('module_execution', {})

    # Legacy
    assert exec_data['LegacyList']['status'] == ModuleExecutionState.RETURNED
    assert 'assessment_outcome' not in exec_data['LegacyList']

    # Completed
    assert exec_data['CompletedMod']['status'] == ModuleExecutionState.RETURNED
    assert exec_data['CompletedMod']['assessment_outcome'] == AssessmentOutcome.COMPLETED

    # Partial
    assert exec_data['PartialMod']['status'] == ModuleExecutionState.RETURNED
    assert exec_data['PartialMod']['assessment_outcome'] == AssessmentOutcome.PARTIAL

    # Not Applicable
    assert exec_data['NAMod']['status'] == ModuleExecutionState.RETURNED
    assert exec_data['NAMod']['assessment_outcome'] == AssessmentOutcome.NOT_APPLICABLE

    # Blocked
    assert exec_data['BlockedMod']['status'] == ModuleExecutionState.RETURNED
    assert exec_data['BlockedMod']['assessment_outcome'] == AssessmentOutcome.BLOCKED

    # Failed
    assert exec_data['FailedMod']['status'] == ModuleExecutionState.FAILED
    assert 'assessment_outcome' not in exec_data['FailedMod']

    # Timeout
    assert exec_data['TimeoutMod']['status'] == ModuleExecutionState.TIMED_OUT
    assert 'assessment_outcome' not in exec_data['TimeoutMod']

# Mock actual modules to ensure they return COMPLETED
from api.scanner.modules.http_security import SecurityHeadersModule, AdvancedCookieModule
from api.scanner.modules.discovery import RobotsTxtModule, SitemapModule

class MockResponse:
    def __init__(self, status_code, text, headers):
        self.status_code = status_code
        self.text = text
        self.headers = headers
        self.raw = type('obj', (object,), {'headers': type('obj', (object,), {'getlist': lambda x: []})})()

def test_security_headers_module():
    mod = SecurityHeadersModule()
    with patch('api.scanner.modules.http_security.safe_request', return_value=MockResponse(200, '', {'Strict-Transport-Security': 'max-age=31536000'})):
        res = mod.run('https://example.com', 'example.com', None)
        assert isinstance(res, ModuleResult)
        assert res.assessment_outcome == AssessmentOutcome.COMPLETED

def test_advanced_cookie_module():
    mod = AdvancedCookieModule()
    with patch('api.scanner.modules.http_security.safe_request', return_value=MockResponse(200, '', {'Set-Cookie': 'session=123'})):
        res = mod.run('https://example.com', 'example.com', None)
        assert isinstance(res, ModuleResult)
        assert res.assessment_outcome == AssessmentOutcome.COMPLETED

def test_advanced_cookie_module_no_cookies():
    mod = AdvancedCookieModule()
    with patch('api.scanner.modules.http_security.safe_request', return_value=MockResponse(200, '', {})):
        res = mod.run('https://example.com', 'example.com', None)
        assert isinstance(res, ModuleResult)
        assert res.assessment_outcome == AssessmentOutcome.COMPLETED

def test_robots_txt_module():
    mod = RobotsTxtModule()
    with patch('api.scanner.modules.discovery.safe_request', return_value=MockResponse(200, 'User-agent: *', {'Content-Type': 'text/plain'})):
        res = mod.run('https://example.com', 'example.com', None)
        assert isinstance(res, ModuleResult)
        assert res.assessment_outcome == AssessmentOutcome.COMPLETED

def test_robots_txt_ambiguous_failure():
    mod = RobotsTxtModule()
    def raise_err(*args, **kwargs):
        raise requests.exceptions.Timeout('timeout')
    with patch('api.scanner.modules.discovery.safe_request', side_effect=raise_err):
        res = mod.run('https://example.com', 'example.com', None)
        # Fallback to findings list when exception swallowed
        assert isinstance(res, list)

def test_sitemap_module():
    mod = SitemapModule()
    with patch('api.scanner.modules.discovery.safe_request', return_value=MockResponse(200, '<?xml version=\'1.0\'?><urlset></urlset>', {'Content-Type': 'application/xml'})):
        res = mod.run('https://example.com', 'example.com', None)
        assert isinstance(res, ModuleResult)
        assert res.assessment_outcome == AssessmentOutcome.COMPLETED

def test_sitemap_ambiguous_failure():
    mod = SitemapModule()
    def raise_err(*args, **kwargs):
        raise requests.exceptions.Timeout('timeout')
    with patch('api.scanner.modules.discovery.safe_request', side_effect=raise_err):
        res = mod.run('https://example.com', 'example.com', None)
        assert isinstance(res, list)
