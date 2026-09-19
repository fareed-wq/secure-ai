import pytest
import copy
from api.scanner.technology_identity import extract_technology_identities, normalize_product, normalize_vendor, get_layer

def test_canonical_aliases():
    assert normalize_product("Nginx") == "nginx"

def test_layer_classification():
    assert get_layer("Next.js") == "application_framework"
    assert get_layer("Nuxt") == "application_framework"

def test_unknown_layer_fallback():
    findings = [{
        "rule_id": "technology_detected",
        "module": "Headers",
        "evidence": {"product": "SomeRandomTech", "version": None, "source": "server header"}
    }]
    idents = extract_technology_identities(findings)
    assert len(idents) == 0

def test_malformed_product():
    findings = [{
        "rule_id": "technology_detected",
        "module": "Headers",
        "evidence": {"product": None, "version": None, "source": "server header"}
    }]
    idents = extract_technology_identities(findings)
    assert len(idents) == 0

def test_malformed_evidence_does_not_suppress():
    findings = [
        {
            "rule_id": "technology_detected",
            "module": "Headers",
            "evidence": None
        },
        {
            "rule_id": "info_disclosure_server_banner",
            "module": "Discovery",
            "evidence": "nginx/1.24.0",
            "confidence": "Medium"
        }
    ]
    idents = extract_technology_identities(findings)
    assert len(idents) == 1
    assert idents[0]["product"] == "nginx"

def test_scoring_includes_technology_identities():
    from api.scanner.scoring import calculate_score
    res = calculate_score("http://example.com", [], {}, None)
    assert "technology_identities" in res
    assert res["technology_identities"] == []

def test_canonical_source_type():
    findings = [{
        "rule_id": "info_disclosure_server_banner",
        "module": "Discovery",
        "evidence": "nginx/1.24.0",
        "confidence": "Medium"
    }]
    idents = extract_technology_identities(findings)
    src = idents[0]["sources"][0]
    assert src["source_type"] == "server_header"

def test_duplicate_stronger_claim():
    findings = [
        {
            "rule_id": "technology_detected",
            "module": "Headers",
            "evidence": {"product": "nginx", "version": "1.24", "source": "html_marker"},
            "confidence": "Low"
        },
        {
            "rule_id": "info_disclosure_server_banner",
            "module": "Discovery",
            "evidence": "nginx/1.24",
            "confidence": "High" # will become Medium, OBSERVED, PARSED_OBSERVED
        }
    ]
    idents = extract_technology_identities(findings)
    assert len(idents) == 1
    assert idents[0]["confidence"] == "Medium"
    assert idents[0]["verification_state"] == "OBSERVED"
    assert idents[0]["version_precision"] == "PARSED_OBSERVED"

def test_true_reversed_input_determinism():
    # TRUE equal-confidence + equal-verification + equal-precision reversed-input test.
    f1 = {
        "rule_id": "technology_detected",
        "module": "A",
        "evidence": {"product": "nginx", "version": "1.24", "source": "server header"},
        "confidence": "Medium" 
    }
    f2 = {
        "rule_id": "technology_detected",
        "module": "B",
        "evidence": {"product": "nginx", "version": "1.24", "source": "server header"},
        "confidence": "Medium" 
    }
    id1 = extract_technology_identities([f1, f2])
    id2 = extract_technology_identities([f2, f1])
    assert id1 == id2

def test_merged_source_ordering():
    findings = [
        {
            "rule_id": "technology_detected",
            "module": "B",
            "evidence": {"product": "nginx", "version": "1.24", "source": "server header"}
        },
        {
            "rule_id": "technology_detected",
            "module": "A",
            "evidence": {"product": "nginx", "version": "1.24", "source": "server header"}
        }
    ]
    idents = extract_technology_identities(findings)
    assert idents[0]["sources"][0]["module"] == "A"
    assert idents[0]["sources"][1]["module"] == "B"

def test_unknown_provenance_excluded():
    findings = [{
        "rule_id": "technology_detected",
        "module": "Headers",
        "evidence": {"product": "React", "version": None, "source": "Some weird magic string"}
    }]
    idents = extract_technology_identities(findings)
    assert len(idents) == 0

def test_js_framework_producer():
    findings = [{
        "rule_id": "technology_js_frameworks_detected",
        "module": "JS",
        "evidence": "Vue.js",
        "confidence": "Medium"
    }]
    idents = extract_technology_identities(findings)
    assert idents[0]["product"] == "Vue.js"
    assert idents[0]["sources"][0]["source_type"] == "js_framework_marker"

def test_generic_technology_producer():
    findings = [{
        "rule_id": "technology_detected",
        "module": "Headers",
        "evidence": {"product": "WordPress", "version": "6.0", "source": "HTML marker"},
        "confidence": "Medium"
    }]
    idents = extract_technology_identities(findings)
    assert idents[0]["product"] == "WordPress"
    assert idents[0]["version"] == "6.0"

def test_server_banner_shape():
    findings = [{
        "rule_id": "info_disclosure_server_banner",
        "module": "Discovery",
        "evidence": "Apache/2.4.41",
        "confidence": "Medium"
    }]
    idents = extract_technology_identities(findings)
    assert idents[0]["product"] == "Apache"
    assert idents[0]["version"] == "2.4.41"

def test_api_v1_v2_excluded():
    findings = [{
        "rule_id": "api_version_disclosed",
        "evidence": "v1, v2"
    }]
    idents = extract_technology_identities(findings)
    assert len(idents) == 0

def test_invariant_scoring_unchanged():
    from api.scanner.scoring import calculate_score
    findings = [
        {
            "name": "Verbose Server Banner",
            "rule_id": "info_disclosure_server_banner",
            "module": "Discovery",
            "evidence": "nginx/1.24.0",
            "severity": "Low",
            "confidence": "High",
            "domain": "browser_defense" # supply this so the engine doesn't modify it
        }
    ]
    findings_copy = copy.deepcopy(findings)
    res_with = calculate_score("http://example.com", findings, {}, None)
    assert findings == findings_copy
    assert res_with["score"] == 98 # Low severity has penalty -2

def test_html_heuristic():
    findings = [{
        "rule_id": "technology_detected",
        "module": "Headers",
        "confidence": "High", 
        "evidence": {"product": "Nuxt", "version": None, "source": "HTML references /_nuxt/"}
    }]
    idents = extract_technology_identities(findings)
    assert idents[0]["product"] == "Nuxt"
    assert idents[0]["confidence"] == "Medium"
    assert idents[0]["version"] is None
    assert idents[0]["version_precision"] == "UNKNOWN"
    assert idents[0]["verification_state"] == "INFERRED"
    assert idents[0]["layer"] == "application_framework"
