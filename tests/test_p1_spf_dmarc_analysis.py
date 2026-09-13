import pytest
import requests
from unittest.mock import MagicMock
from api.scanner.modules.dns import DNSEmailSecurityModule

def create_mock_response(status_code, json_data):
    mock = MagicMock()
    mock.status_code = status_code
    mock.json.return_value = json_data
    return mock

@pytest.fixture
def module():
    return DNSEmailSecurityModule()

@pytest.fixture
def session():
    return requests.Session()

def mock_safe_request(mock_answers, dmarc_answers=None, mta_answers=None, dkim_answers=None):
    def _mock_req(method, url, **kwargs):
        if "_dmarc" in url:
            if dmarc_answers: return create_mock_response(200, {"Status": 0, "Answer": dmarc_answers})
        elif "_mta-sts" in url:
            if mta_answers: return create_mock_response(200, {"Status": 0, "Answer": mta_answers})
        elif "_domainkey" in url:
            if dkim_answers: return create_mock_response(200, {"Status": 0, "Answer": dkim_answers})
        else:
            if mock_answers: return create_mock_response(200, {"Status": 0, "Answer": mock_answers})
        return create_mock_response(200, {"Status": 0})
    return _mock_req

# ======================= SPF TESTS =======================

def test_spf_minus_all(module, session, monkeypatch):
    answers = [{"data": "v=spf1 ip4:1.2.3.4 -all"}]
    monkeypatch.setattr("api.scanner.modules.dns.safe_request", mock_safe_request(answers))
    findings = module.run("https://example.com", "example.com", session)

    spf_passed = next((f for f in findings if f["name"] == "SPF Record Configured"), None)
    spf_info = next((f for f in findings if f["name"] == "SPF Policy Analysis"), None)

    assert spf_passed is not None
    assert spf_info is not None
    assert "Strict fail policy (-all)" in spf_info["description"]
    # removed

def test_spf_tilde_all(module, session, monkeypatch):
    answers = [{"data": "v=spf1 include:_spf.google.com ~all"}]
    monkeypatch.setattr("api.scanner.modules.dns.safe_request", mock_safe_request(answers))
    findings = module.run("https://example.com", "example.com", session)

    spf_passed = next((f for f in findings if f["name"] == "SPF Record Configured"), None)
    spf_info = next((f for f in findings if f["name"] == "SPF Policy Analysis"), None)

    assert spf_passed is not None
    assert spf_info is not None
    assert "Softfail policy (~all)" in spf_info["description"]
    assert "Includes other domains: 1" in spf_info["description"]

def test_spf_question_all(module, session, monkeypatch):
    answers = [{"data": "v=spf1 ?all"}]
    monkeypatch.setattr("api.scanner.modules.dns.safe_request", mock_safe_request(answers))
    findings = module.run("https://example.com", "example.com", session)

    spf_passed = next((f for f in findings if f["name"] == "SPF Record Configured"), None)
    spf_info = next((f for f in findings if f["name"] == "SPF Policy Analysis"), None)

    assert spf_passed is None
    assert spf_info is not None
    assert "Neutral policy (?all)" in spf_info["description"]

def test_spf_plus_all_regression(module, session, monkeypatch):
    answers = [{"data": "v=spf1 +all"}]
    monkeypatch.setattr("api.scanner.modules.dns.safe_request", mock_safe_request(answers))
    findings = module.run("https://example.com", "example.com", session)

    overly = next((f for f in findings if f["name"] == "Overly Permissive SPF Record"), None)
    assert overly is not None
    assert overly["severity"] == "High"

def test_spf_include_counting(module, session, monkeypatch):
    answers = [{"data": "v=spf1 include:a.com include:b.com -all"}]
    monkeypatch.setattr("api.scanner.modules.dns.safe_request", mock_safe_request(answers))
    findings = module.run("https://example.com", "example.com", session)
    spf_info = next((f for f in findings if f["name"] == "SPF Policy Analysis"), None)
    assert "Includes other domains: 2" in spf_info["description"]

def test_spf_redirect(module, session, monkeypatch):
    answers = [{"data": "v=spf1 redirect=_spf.example.com"}]
    monkeypatch.setattr("api.scanner.modules.dns.safe_request", mock_safe_request(answers))
    findings = module.run("https://example.com", "example.com", session)
    spf_info = next((f for f in findings if f["name"] == "SPF Policy Analysis"), None)
    assert "Redirects to another domain: 1" in spf_info["description"]

def test_spf_malformed_version(module, session, monkeypatch):
    answers = [{"data": "v=spf1-invalid a -all"}]
    monkeypatch.setattr("api.scanner.modules.dns.safe_request", mock_safe_request(answers))
    findings = module.run("https://example.com", "example.com", session)
    # The current module logic requires exactly "v=spf1" in the string to even process it.
    # Since "v=spf1" is technically in "v=spf1-invalid", it processes it.
    malformed = next((f for f in findings if "Version Not First" in f["name"]), None)
    assert malformed is not None
    assert malformed["severity"] == "Low"

def test_spf_multiple_all(module, session, monkeypatch):
    answers = [{"data": "v=spf1 a -all ~all"}]
    monkeypatch.setattr("api.scanner.modules.dns.safe_request", mock_safe_request(answers))
    findings = module.run("https://example.com", "example.com", session)
    malformed = next((f for f in findings if "Multiple 'all'" in f["name"]), None)
    assert malformed is not None
    assert malformed["severity"] == "Low"

# ======================= DMARC TESTS =======================

def test_dmarc_p_none_regression(module, session, monkeypatch):
    dmarc = [{"data": "v=DMARC1; p=none;"}]
    monkeypatch.setattr("api.scanner.modules.dns.safe_request", mock_safe_request(None, dmarc))
    findings = module.run("https://example.com", "example.com", session)
    none_finding = next((f for f in findings if f["name"] == "DMARC Monitoring-Only Policy"), None)
    assert none_finding is not None

def test_dmarc_p_quarantine(module, session, monkeypatch):
    dmarc = [{"data": "v=DMARC1; p=quarantine;"}]
    monkeypatch.setattr("api.scanner.modules.dns.safe_request", mock_safe_request(None, dmarc))
    findings = module.run("https://example.com", "example.com", session)
    passed = next((f for f in findings if f["name"] == "Strong DMARC Policy Configured"), None)
    info = next((f for f in findings if f["name"] == "DMARC Policy Analysis"), None)
    assert passed is not None
    assert "Enforcement policy: quarantine" in info["description"]

def test_dmarc_p_reject(module, session, monkeypatch):
    dmarc = [{"data": "v=DMARC1; p=reject;"}]
    monkeypatch.setattr("api.scanner.modules.dns.safe_request", mock_safe_request(None, dmarc))
    findings = module.run("https://example.com", "example.com", session)
    passed = next((f for f in findings if f["name"] == "Strong DMARC Policy Configured"), None)
    info = next((f for f in findings if f["name"] == "DMARC Policy Analysis"), None)
    assert passed is not None
    assert "Enforcement policy: reject" in info["description"]

def test_dmarc_pct_100(module, session, monkeypatch):
    dmarc = [{"data": "v=DMARC1; p=reject; pct=100;"}]
    monkeypatch.setattr("api.scanner.modules.dns.safe_request", mock_safe_request(None, dmarc))
    findings = module.run("https://example.com", "example.com", session)
    info = next((f for f in findings if f["name"] == "DMARC Policy Analysis"), None)
    assert "Policy percentage: 100" not in info["description"] # pct=100 is default, omitted
    disabled = next((f for f in findings if "pct=0" in f["name"]), None)
    assert disabled is None

def test_dmarc_pct_50(module, session, monkeypatch):
    dmarc = [{"data": "v=DMARC1; p=quarantine; pct=50;"}]
    monkeypatch.setattr("api.scanner.modules.dns.safe_request", mock_safe_request(None, dmarc))
    findings = module.run("https://example.com", "example.com", session)
    info = next((f for f in findings if f["name"] == "DMARC Policy Analysis"), None)
    assert "Policy percentage: 50%" in info["description"]
    disabled = next((f for f in findings if "pct=0" in f["name"]), None)
    assert disabled is None

def test_dmarc_pct_0(module, session, monkeypatch):
    dmarc = [{"data": "v=DMARC1; p=reject; pct=0;"}]
    monkeypatch.setattr("api.scanner.modules.dns.safe_request", mock_safe_request(None, dmarc))
    findings = module.run("https://example.com", "example.com", session)
    disabled = next((f for f in findings if f["name"] == "DMARC Enforcement Disabled by pct=0"), None)
    assert disabled is not None
    assert disabled["severity"] == "Low"

def test_dmarc_sp_none(module, session, monkeypatch):
    dmarc = [{"data": "v=DMARC1; p=reject; sp=none;"}]
    monkeypatch.setattr("api.scanner.modules.dns.safe_request", mock_safe_request(None, dmarc))
    findings = module.run("https://example.com", "example.com", session)
    info = next((f for f in findings if f["name"] == "DMARC Policy Analysis"), None)
    assert "Subdomain policy: none" in info["description"]

def test_dmarc_rua_ruf_adkim_aspf(module, session, monkeypatch):
    dmarc = [{"data": "v=DMARC1; p=reject; rua=mailto:x@y.com; ruf=mailto:x@y.com; adkim=s; aspf=r;"}]
    monkeypatch.setattr("api.scanner.modules.dns.safe_request", mock_safe_request(None, dmarc))
    findings = module.run("https://example.com", "example.com", session)
    info = next((f for f in findings if f["name"] == "DMARC Policy Analysis"), None)
    assert "Aggregate reporting (rua) enabled" in info["description"]
    assert "Forensic reporting (ruf) enabled" in info["description"]
    assert "DKIM alignment: s" in info["description"]
    assert "SPF alignment: r" in info["description"]

def test_dmarc_duplicate_tags(module, session, monkeypatch):
    dmarc = [{"data": "v=DMARC1; p=reject; p=quarantine;"}]
    monkeypatch.setattr("api.scanner.modules.dns.safe_request", mock_safe_request(None, dmarc))
    findings = module.run("https://example.com", "example.com", session)
    dup = next((f for f in findings if "Duplicate Tags" in f["name"]), None)
    assert dup is not None
    assert "p" in dup["description"]

def test_dmarc_malformed(module, session, monkeypatch):
    dmarc = [{"data": "p=reject; v=DMARC1;"}] # v=DMARC1 not first
    monkeypatch.setattr("api.scanner.modules.dns.safe_request", mock_safe_request(None, dmarc))
    findings = module.run("https://example.com", "example.com", session)
    mal = next((f for f in findings if f["name"] == "Malformed DMARC Record"), None)
    assert mal is not None

def test_zero_new_network_requests(module, session, monkeypatch):
    # Track calls
    call_count = 0
    def _tracking_req(method, url, **kwargs):
        nonlocal call_count
        call_count += 1
        return mock_safe_request(None, None)(method, url, **kwargs)

    monkeypatch.setattr("api.scanner.modules.dns.safe_request", _tracking_req)
    module.run("https://example.com", "example.com", session)

    # 1 SPF, 1 DMARC, 1 MTA-STS, up to 3 DKIM (since mock returns nothing, loop continues 3 times)
    assert call_count == 3

def test_dmarc_pct_100(module, session, monkeypatch):
    answers = [{"data": "v=DMARC1; p=quarantine; pct=100"}]
    monkeypatch.setattr("api.scanner.modules.dns.safe_request", mock_safe_request(answers, dmarc_answers=answers))
    findings = module.run("https://example.com", "example.com", session)
    passed = next((f for f in findings if f["name"] == "Strong DMARC Policy Configured"), None)
    assert passed is not None

def test_dmarc_pct_0100(module, session, monkeypatch):
    answers = [{"data": "v=DMARC1; p=quarantine; pct=0100"}]
    monkeypatch.setattr("api.scanner.modules.dns.safe_request", mock_safe_request(answers, dmarc_answers=answers))
    findings = module.run("https://example.com", "example.com", session)
    passed = next((f for f in findings if f["name"] == "Strong DMARC Policy Configured"), None)
    assert passed is not None

def test_dmarc_pct_0(module, session, monkeypatch):
    answers = [{"data": "v=DMARC1; p=quarantine; pct=0"}]
    monkeypatch.setattr("api.scanner.modules.dns.safe_request", mock_safe_request(answers, dmarc_answers=answers))
    findings = module.run("https://example.com", "example.com", session)
    disabled = next((f for f in findings if f["name"] == "DMARC Enforcement Disabled by pct=0"), None)
    passed = next((f for f in findings if f["name"] == "Strong DMARC Policy Configured"), None)
    assert disabled is not None
    assert passed is None

def test_dmarc_pct_000(module, session, monkeypatch):
    answers = [{"data": "v=DMARC1; p=quarantine; pct=000"}]
    monkeypatch.setattr("api.scanner.modules.dns.safe_request", mock_safe_request(answers, dmarc_answers=answers))
    findings = module.run("https://example.com", "example.com", session)
    disabled = next((f for f in findings if f["name"] == "DMARC Enforcement Disabled by pct=0"), None)
    passed = next((f for f in findings if f["name"] == "Strong DMARC Policy Configured"), None)
    assert disabled is not None
    assert passed is None

def test_dmarc_pct_50(module, session, monkeypatch):
    answers = [{"data": "v=DMARC1; p=quarantine; pct=50"}]
    monkeypatch.setattr("api.scanner.modules.dns.safe_request", mock_safe_request(answers, dmarc_answers=answers))
    findings = module.run("https://example.com", "example.com", session)
    partial = next((f for f in findings if f["name"] == "Partial DMARC Enforcement"), None)
    passed = next((f for f in findings if f["name"] == "Strong DMARC Policy Configured"), None)
    assert partial is not None
    assert passed is None

def test_dmarc_pct_050(module, session, monkeypatch):
    answers = [{"data": "v=DMARC1; p=quarantine; pct=050"}]
    monkeypatch.setattr("api.scanner.modules.dns.safe_request", mock_safe_request(answers, dmarc_answers=answers))
    findings = module.run("https://example.com", "example.com", session)
    partial = next((f for f in findings if f["name"] == "Partial DMARC Enforcement"), None)
    passed = next((f for f in findings if f["name"] == "Strong DMARC Policy Configured"), None)
    assert partial is not None
    assert passed is None

def test_dmarc_pct_invalid(module, session, monkeypatch):
    for invalid_pct in ["abc", "-1", "101"]:
        answers = [{"data": f"v=DMARC1; p=quarantine; pct={invalid_pct}"}]
        monkeypatch.setattr("api.scanner.modules.dns.safe_request", mock_safe_request(answers, dmarc_answers=answers))
        findings = module.run("https://example.com", "example.com", session)
        malformed = next((f for f in findings if f["name"] == "Malformed DMARC Record"), None)
        passed = next((f for f in findings if f["name"] == "Strong DMARC Policy Configured"), None)
        assert malformed is not None
        assert passed is None



def test_3b2_dmarc_additional(module, session, monkeypatch):
    def mock_query_dmarc_mal(domain, rtype, session):
        if domain.startswith("_dmarc."):
            return {"Status": 0, "Answer": [{"data": "v=DMARC1; p=none; pct=0; p=none"}]}
        if rtype == "MX": return {"Status": 0, "Answer": [{"data": "mx"}]}
        return {"Status": 0}
    monkeypatch.setattr("api.scanner.modules.dns.query_doh", mock_query_dmarc_mal)
    findings = module.run("https://example.com", "example.com", session)

    dup = next((f for f in findings if f["name"] == "Malformed DMARC Record (Duplicate Tags)"), None)
    assert dup and dup.get("rule_id") == "dns_email_dmarc_malformed_duplicate_tags"
    assert "instance_key" not in dup

    def mock_query_dmarc_mal2(domain, rtype, session):
        if domain.startswith("_dmarc."):
            return {"Status": 0, "Answer": [{"data": "p=none; v=DMARC1;"}]}
        if rtype == "MX": return {"Status": 0, "Answer": [{"data": "mx"}]}
        return {"Status": 0}
    monkeypatch.setattr("api.scanner.modules.dns.query_doh", mock_query_dmarc_mal2)
    findings = module.run("https://example.com", "example.com", session)
    mal = next((f for f in findings if f["name"] == "Malformed DMARC Record"), None)
    assert mal and mal.get("rule_id") == "dns_email_dmarc_malformed"
    assert "instance_key" not in mal

    def mock_query_dmarc_pct0(domain, rtype, session):
        if domain.startswith("_dmarc."):
            return {"Status": 0, "Answer": [{"data": "v=DMARC1; p=reject; pct=0"}]}
        if rtype == "MX": return {"Status": 0, "Answer": [{"data": "mx"}]}
        return {"Status": 0}
    monkeypatch.setattr("api.scanner.modules.dns.query_doh", mock_query_dmarc_pct0)
    findings = module.run("https://example.com", "example.com", session)
    pct0 = next((f for f in findings if f["name"] == "DMARC Enforcement Disabled by pct=0"), None)
    assert pct0 and pct0.get("rule_id") == "dns_email_dmarc_pct_zero"
    assert "instance_key" not in pct0

    def mock_query_dmarc_partial(domain, rtype, session):
        if domain.startswith("_dmarc."):
            return {"Status": 0, "Answer": [{"data": "v=DMARC1; p=quarantine; pct=50"}]}
        if rtype == "MX": return {"Status": 0, "Answer": [{"data": "mx"}]}
        return {"Status": 0}
    monkeypatch.setattr("api.scanner.modules.dns.query_doh", mock_query_dmarc_partial)
    findings = module.run("https://example.com", "example.com", session)
    partial = next((f for f in findings if f["name"] == "Partial DMARC Enforcement"), None)
    assert partial and partial.get("rule_id") == "dns_email_dmarc_partial_enforcement"
    assert "instance_key" not in partial



def test_3b2_spf_dmarc_identities(module, session, monkeypatch):
    monkeypatch.setattr("api.scanner.modules.dns.safe_request", lambda *a, **kw: MagicMock())

    # Missing
    def mock_query_miss(domain, rtype, session):
        if rtype == "MX": return {"Status": 0, "Answer": [{"data": "mx"}]}
        return {"Status": 0}
    monkeypatch.setattr("api.scanner.modules.dns.query_doh", mock_query_miss)
    findings = module.run("https://example.com", "example.com", session)
    spf = next((f for f in findings if f["name"] == "SPF Record Not Observed"), None)
    assert spf and spf.get("rule_id") == "dns_email_spf_missing"
    dm = next((f for f in findings if f["name"] == "DMARC Record Not Observed"), None)
    assert dm and dm.get("rule_id") == "dns_email_dmarc_missing"

    # Ok
    def mock_query_ok(domain, rtype, session):
        if rtype == "TXT" and not domain.startswith("_dmarc") and not domain.startswith("_mta-sts"):
            return {"Status": 0, "Answer": [{"data": "v=spf1 ~all"}]}
        elif rtype == "TXT" and domain.startswith("_dmarc"):
            return {"Status": 0, "Answer": [{"data": "v=DMARC1; p=reject"}]}
        elif rtype == "TXT" and domain.startswith("_mta-sts"):
            return {"Status": 0, "Answer": [{"data": "v=STSv1; id=123"}]}
        elif rtype == "MX": return {"Status": 0, "Answer": [{"data": "mx"}]}
        return {"Status": 0}
    monkeypatch.setattr("api.scanner.modules.dns.query_doh", mock_query_ok)
    findings = module.run("https://example.com", "example.com", session)
    spf_c = next((f for f in findings if f["name"] == "SPF Record Configured"), None)
    assert spf_c and spf_c.get("rule_id") == "dns_email_spf_configured"
    dm_c = next((f for f in findings if f["name"] == "Strong DMARC Policy Configured"), None)
    assert dm_c and dm_c.get("rule_id") == "dns_email_dmarc_strong"
    mta = next((f for f in findings if f["name"] == "MTA-STS TXT Record Observed"), None)
    assert mta and mta.get("rule_id") == "dns_email_mta_sts_observed"

    # Multiples
    def mock_query_mult(domain, rtype, session):
        if rtype == "TXT" and not domain.startswith("_dmarc") and not domain.startswith("_mta-sts"):
            return {"Status": 0, "Answer": [{"data": "v=spf1"}, {"data": "v=spf1"}]}
        elif rtype == "TXT" and domain.startswith("_dmarc"):
            return {"Status": 0, "Answer": [{"data": "v=DMARC1; p=none"}, {"data": "v=DMARC1; p=reject"}]}
        return {"Status": 0}
    monkeypatch.setattr("api.scanner.modules.dns.query_doh", mock_query_mult)
    findings = module.run("https://example.com", "example.com", session)
    assert next((f for f in findings if f["name"] == "Multiple SPF Records Detected"), None).get("rule_id") == "dns_email_spf_multiple"
    assert next((f for f in findings if f["name"] == "Multiple DMARC Records Detected"), None).get("rule_id") == "dns_email_dmarc_multiple"

    # Permissive and Malformed SPF
    def mock_query_perm(domain, rtype, session):
        if rtype == "TXT" and not domain.startswith("_dmarc") and not domain.startswith("_mta-sts"):
            return {"Status": 0, "Answer": [{"data": "v=spf1 +all"}]}
        return {"Status": 0}
    monkeypatch.setattr("api.scanner.modules.dns.query_doh", mock_query_perm)
    findings = module.run("https://example.com", "example.com", session)
    assert next((f for f in findings if f["name"] == "Overly Permissive SPF Record"), None).get("rule_id") == "dns_email_spf_permissive"

    def mock_query_mal_all(domain, rtype, session):
        if rtype == "TXT" and not domain.startswith("_dmarc") and not domain.startswith("_mta-sts"):
            return {"Status": 0, "Answer": [{"data": "v=spf1 -all ~all"}]}
        return {"Status": 0}
    monkeypatch.setattr("api.scanner.modules.dns.query_doh", mock_query_mal_all)
    findings = module.run("https://example.com", "example.com", session)
    assert next((f for f in findings if f["name"] == "Malformed SPF Record (Multiple 'all' mechanisms)"), None).get("rule_id") == "dns_email_spf_malformed_multiple_all"
