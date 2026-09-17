import pytest
from unittest.mock import MagicMock, patch
from api.scanner.modules.discovery import InformationDisclosureModule

def run_module(text_content):
    with patch('api.scanner.modules.discovery.safe_request') as mock_safe_req:
        mod = InformationDisclosureModule()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = text_content
        mock_resp.headers = {'Content-Type': 'text/html'}
        mock_safe_req.return_value = mock_resp
        return mod.run('http://example.com', 'example.com', session=MagicMock())

# TRUE POSITIVES
def test_valid_1():
    findings = run_module('10.0.0.1')
    assert any(f.get('rule_id') == 'info_disclosure_private_ip' for f in findings)

def test_valid_2():
    findings = run_module('10.255.255.254')
    assert any(f.get('rule_id') == 'info_disclosure_private_ip' for f in findings)

def test_valid_3():
    findings = run_module('172.16.0.1')
    assert any(f.get('rule_id') == 'info_disclosure_private_ip' for f in findings)

def test_valid_4():
    findings = run_module('172.31.255.254')
    assert any(f.get('rule_id') == 'info_disclosure_private_ip' for f in findings)

def test_valid_5():
    findings = run_module('192.168.1.1')
    assert any(f.get('rule_id') == 'info_disclosure_private_ip' for f in findings)

def test_valid_6():
    findings = run_module('192.168.255.254')
    assert any(f.get('rule_id') == 'info_disclosure_private_ip' for f in findings)

# FALSE POSITIVES (OUTSIDE RANGE)
def test_invalid_1():
    findings = run_module('11.0.0.1')
    assert not any(f.get('rule_id') == 'info_disclosure_private_ip' for f in findings)

def test_invalid_2():
    findings = run_module('172.15.0.1')
    assert not any(f.get('rule_id') == 'info_disclosure_private_ip' for f in findings)

def test_invalid_3():
    findings = run_module('172.32.0.1')
    assert not any(f.get('rule_id') == 'info_disclosure_private_ip' for f in findings)

def test_invalid_4():
    findings = run_module('192.167.1.1')
    assert not any(f.get('rule_id') == 'info_disclosure_private_ip' for f in findings)

def test_invalid_5():
    findings = run_module('192.169.1.1')
    assert not any(f.get('rule_id') == 'info_disclosure_private_ip' for f in findings)

# FALSE POSITIVES (INVALID OCTETS)
def test_octet_1():
    findings = run_module('10.999.1.1')
    assert not any(f.get('rule_id') == 'info_disclosure_private_ip' for f in findings)

def test_octet_2():
    findings = run_module('10.386.748.748')
    assert not any(f.get('rule_id') == 'info_disclosure_private_ip' for f in findings)

def test_octet_3():
    findings = run_module('10.669.606.225')
    assert not any(f.get('rule_id') == 'info_disclosure_private_ip' for f in findings)

def test_octet_4():
    findings = run_module('192.168.300.1')
    assert not any(f.get('rule_id') == 'info_disclosure_private_ip' for f in findings)

def test_octet_5():
    findings = run_module('172.16.999.1')
    assert not any(f.get('rule_id') == 'info_disclosure_private_ip' for f in findings)

# BOUNDARIES
def test_boundary_1():
    findings = run_module('110.0.0.1')
    assert not any(f.get('rule_id') == 'info_disclosure_private_ip' for f in findings)

def test_boundary_2():
    findings = run_module('x10.0.0.1')
    assert not any(f.get('rule_id') == 'info_disclosure_private_ip' for f in findings)

def test_boundary_3():
    findings = run_module('10.0.0.1x')
    assert not any(f.get('rule_id') == 'info_disclosure_private_ip' for f in findings)

def test_boundary_4():
    findings = run_module('10.0.0.1.5')
    assert not any(f.get('rule_id') == 'info_disclosure_private_ip' for f in findings)

def test_boundary_5():
    findings = run_module('192.168.1.10.20')
    assert not any(f.get('rule_id') == 'info_disclosure_private_ip' for f in findings)

# REALISTIC
def test_context_1():
    findings = run_module('http://10.0.0.5/api')
    assert any(f.get('rule_id') == 'info_disclosure_private_ip' for f in findings)

def test_context_2():
    findings = run_module('https://192.168.1.10/internal')
    assert any(f.get('rule_id') == 'info_disclosure_private_ip' for f in findings)

def test_context_3():
    findings = run_module('internalHost="172.16.1.5"')
    assert any(f.get('rule_id') == 'info_disclosure_private_ip' for f in findings)
