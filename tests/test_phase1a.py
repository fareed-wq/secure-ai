import pytest
from api.scanner.base import ScannerModule
from api.scanner.core import VerificationState

class DummyModule(ScannerModule):
    module_name = "Dummy"
    def run(self, url, hostname, session):
        return []

def test_legacy_string_evidence():
    mod = DummyModule()
    finding = mod.make_finding("Test", "Low", "Desc", "A long string" * 50, confidence="High")
    assert "raw" in finding["evidence"]
    assert len(finding["evidence"]["raw"]) == 180
    assert finding.get("state") is None

def test_structured_dict_evidence():
    mod = DummyModule()
    finding = mod.make_finding("Test", "Low", "Desc", {"method": "GET"}, verification_state=VerificationState.OBSERVED, confidence="High")
    assert finding["evidence"]["method"] == "GET"
    assert finding["state"] == "Observed"

def test_nested_evidence():
    mod = DummyModule()
    finding = mod.make_finding("Test", "Low", "Desc", {"req": {"headers": {"host": "example.com"}}}, confidence="High")
    assert finding["evidence"]["req"]["headers"]["host"] == "example.com"
    assert finding.get("state") is None

def test_redaction_in_structured_evidence():
    mod = DummyModule()
    # AWS key dummy: AKIAIOSFODNN7EXAMPLE
    finding = mod.make_finding("Test", "Low", "Desc", {"req": "AKIAIOSFODNN7EXAMPLE", "arr": ["sk_live_12345"]}, confidence="High")
    assert "AKIA" not in finding["evidence"]["req"]
    assert "[REDACTED_AWS]" in finding["evidence"]["req"]
    assert "sk_live_" not in finding["evidence"]["arr"][0]
    assert "[REDACTED_STRIPE]" in finding["evidence"]["arr"][0]

def test_clipping_in_structured_evidence():
    mod = DummyModule()
    long_str = "A" * 1000
    finding = mod.make_finding("Test", "Low", "Desc", {"short": "B", "long": long_str, "nested": {"deep": long_str}, "arr": [long_str]}, confidence="High")
    assert finding["evidence"]["short"] == "B"
    assert len(finding["evidence"]["long"]) == 180
    assert len(finding["evidence"]["nested"]["deep"]) == 180
    assert len(finding["evidence"]["arr"][0]) == 180

def test_states():
    mod = DummyModule()
    f1 = mod.make_finding("Test", "Low", "Desc", "Ev", verification_state=VerificationState.OBSERVED, confidence="High")
    f2 = mod.make_finding("Test", "Low", "Desc", "Ev", verification_state=VerificationState.INFERRED, confidence="High")
    f3 = mod.make_finding("Test", "Low", "Desc", "Ev", verification_state=VerificationState.NOT_VERIFIED, confidence="High")

    assert f1["state"] == "Observed"
    assert f2["state"] == "Inferred"
    assert f3["state"] == "Not Verified"

def test_omitted_verification_state():
    mod = DummyModule()
    f1 = mod.make_finding("Test", "Low", "Desc", "Ev", confidence="High")
    assert "state" in f1
    assert f1["state"] is None

def test_rule_id_and_instance_key_preserved():
    mod = DummyModule()
    f1 = mod.make_finding("Test", "Low", "Desc", "Ev", rule_id="rule1", instance_key="inst1", confidence="High")
    assert f1["rule_id"] == "rule1"
    assert f1["instance_key"] == "inst1"
