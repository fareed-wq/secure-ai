import pytest

from api.scanner.technology_identity import extract_technology_identities



def test_supported_cpe_mapping():

    findings = [

        {"rule_id": "info_disclosure_server_banner", "module": "Discovery", "evidence": "nginx/1.24.0", "confidence": "Medium"},

        {"rule_id": "info_disclosure_server_banner", "module": "Discovery", "evidence": "IIS/10.0", "confidence": "Medium"},

        {"rule_id": "info_disclosure_server_banner", "module": "Discovery", "evidence": "Apache/2.4.41", "confidence": "Medium"},

        {"rule_id": "technology_outdated_library", "module": "JS", "evidence": "React v16.0.0", "confidence": "Medium"},

        {"rule_id": "technology_outdated_library", "module": "JS", "evidence": "Vue.js v2.5.0", "confidence": "Medium"},

        {"rule_id": "technology_outdated_library", "module": "JS", "evidence": "jQuery v3.5.1", "confidence": "Medium"},

        {"rule_id": "technology_detected", "module": "Headers", "evidence": {"product": "WordPress", "version": "6.0", "source": "html_marker"}, "confidence": "Medium"},

        {"rule_id": "technology_detected", "module": "Headers", "evidence": {"product": "PHP", "version": "8.1.0", "source": "server_header"}, "confidence": "Medium"},

        {"rule_id": "technology_detected", "module": "Headers", "evidence": {"product": "Node.js", "version": "18.0", "source": "server_header"}, "confidence": "Medium"}

    ]

    idents = extract_technology_identities(findings)

    cpes = {i["product"]: i["cpe"] for i in idents}

    

    assert cpes["nginx"] == "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"

    assert cpes["Microsoft IIS"] == "cpe:2.3:a:microsoft:internet_information_services:10.0:*:*:*:*:*:*:*"

    assert cpes["Apache"] == "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"

    assert cpes["React"] == "cpe:2.3:a:facebook:react:16.0.0:*:*:*:*:*:*:*"

    assert cpes["Vue.js"] == "cpe:2.3:a:vuejs:vue:2.5.0:*:*:*:*:*:*:*"

    assert cpes["jQuery"] == "cpe:2.3:a:jquery:jquery:3.5.1:*:*:*:*:*:*:*"

    assert cpes["WordPress"] == "cpe:2.3:a:wordpress:wordpress:6.0:*:*:*:*:*:*:*"

    assert cpes["PHP"] == "cpe:2.3:a:php:php:8.1.0:*:*:*:*:*:*:*"

    assert cpes["Node.js"] == "cpe:2.3:a:nodejs:node.js:18.0:*:*:*:*:*:*:*"



def test_missing_version_cpe():

    findings = [{"rule_id": "technology_js_frameworks_detected", "module": "JS", "evidence": "React", "confidence": "Medium"}]

    idents = extract_technology_identities(findings)

    assert idents[0]["cpe"] is None



def test_unknown_product_cpe():

    findings = [{"rule_id": "technology_detected", "module": "Headers", "evidence": {"product": "Nuxt", "version": "2.0", "source": "HTML marker"}, "confidence": "Medium"}]

    idents = extract_technology_identities(findings)

    assert idents[0]["cpe"] is None



def test_ambiguous_product_cpe():

    findings = [{"rule_id": "technology_detected", "module": "Headers", "evidence": {"product": "Express", "version": "4.0", "source": "HTML marker"}, "confidence": "Medium"}]

    idents = extract_technology_identities(findings)

    assert idents[0]["cpe"] is None



def test_inferred_precision_cpe():

    # If a duplicate merge or specific rule ever assigned INFERRED, CPE must be null.

    # We will test _generate_cpe directly for precision handling.

    from api.scanner.technology_identity import _generate_cpe

    assert _generate_cpe("nginx", "1.24.0", "INFERRED") is None

    assert _generate_cpe("nginx", "1.24.0", "UNKNOWN") is None

    assert _generate_cpe("nginx", "1.24.0", "PARSED_OBSERVED") == "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"

    assert _generate_cpe("nginx", "1.24.0", "EXACT_OBSERVED") == "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"



def test_duplicate_merge_preserves_cpe():

    findings = [

        {"rule_id": "technology_detected", "module": "Headers", "evidence": {"product": "nginx", "version": "1.24", "source": "header"}, "confidence": "Low"},

        {"rule_id": "info_disclosure_server_banner", "module": "Discovery", "evidence": "nginx/1.24", "confidence": "High"}

    ]

    idents = extract_technology_identities(findings)

    assert len(idents) == 1

    assert idents[0]["cpe"] == "cpe:2.3:a:nginx:nginx:1.24:*:*:*:*:*:*:*"



def test_malformed_version_cpe():

    findings = [{"rule_id": "technology_detected", "module": "Headers", "evidence": {"product": "nginx", "version": "1.24+malformed space", "source": "server header"}, "confidence": "Medium"}]

    idents = extract_technology_identities(findings)

    assert idents[0]["cpe"] is None



def test_scoring_invariant():

    from api.scanner.scoring import calculate_score

    import copy

    findings = [{"name": "Test Finding", "rule_id": "info_disclosure_server_banner", "module": "Discovery", "evidence": "nginx/1.24.0", "severity": "Low", "confidence": "High", "domain": "browser_defense"}]

    

    findings_copy = copy.deepcopy(findings)

    res_before = calculate_score("http://test", findings_copy, {}, None)

    

    res_after = calculate_score("http://test", findings, {}, None)

    

    assert res_after["score"] == res_before["score"]

    assert res_after["penalties"] == res_before["penalties"]

    assert res_after["findings"] == findings_copy

    assert res_after["technology_identities"][0]["cpe"] == "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"



def test_deterministic_cpe_generation():

    from api.scanner.technology_identity import extract_technology_identities

    

    findings = [

        {"rule_id": "info_disclosure_server_banner", "module": "Discovery", "evidence": "nginx/1.24.0", "confidence": "Medium"},

    ]

    

    idents1 = extract_technology_identities(findings)

    idents2 = extract_technology_identities(findings)

    

    assert idents1 == idents2

    assert idents1[0]["cpe_candidate"] == idents2[0]["cpe_candidate"]

    assert idents1[0]["cpe_authority"] == idents2[0]["cpe_authority"]

    assert idents1[0]["cpe_match_confidence"] == idents2[0]["cpe_match_confidence"]



def test_cpe_authority_levels():

    from api.scanner.technology_identity import extract_technology_identities

    

    findings_obs = [

        {"rule_id": "info_disclosure_server_banner", "module": "Discovery", "evidence": "nginx/1.24.0", "confidence": "Medium"},

    ]

    idents_obs = extract_technology_identities(findings_obs)

    assert idents_obs[0]["cpe_authority"] == "AUTHORITATIVE"

    assert idents_obs[0]["cpe_match_confidence"] == "HIGH"

    

    findings_inferred = [

        {"rule_id": "technology_detected", "module": "Headers", "evidence": {"product": "nginx", "version": "1.24.0", "source": "js_asset"}, "confidence": "Medium"},

    ]

    idents_inferred = extract_technology_identities(findings_inferred)

    assert idents_inferred[0]["cpe_authority"] == "CANDIDATE"

    assert idents_inferred[0]["cpe_match_confidence"] == "MEDIUM"



def test_version_preservation_no_truncation():

    from api.scanner.technology_identity import extract_technology_identities

    

    findings = [

        {"rule_id": "info_disclosure_server_banner", "module": "Discovery", "evidence": "nginx/1.24.0.1", "confidence": "Medium"},

    ]

    idents = extract_technology_identities(findings)

    

    assert idents[0]["version"] == "1.24.0.1"

    assert idents[0]["cpe_candidate"] == "cpe:2.3:a:nginx:nginx:1.24.0.1:*:*:*:*:*:*:*"



def test_deterministic_ordering():

    from api.scanner.technology_identity import extract_technology_identities

    

    findings = [

        {"rule_id": "info_disclosure_server_banner", "module": "Discovery", "evidence": "nginx/1.24.0", "confidence": "Medium"},

        {"rule_id": "info_disclosure_server_banner", "module": "Discovery", "evidence": "Apache/2.4.41", "confidence": "Medium"},

        {"rule_id": "info_disclosure_server_banner", "module": "Discovery", "evidence": "Microsoft IIS/10.0", "confidence": "Medium"},

    ]

    

    idents1 = extract_technology_identities(findings)

    idents2 = extract_technology_identities(findings)

    

    assert idents1 == idents2

    # Deterministic ordering by layer, vendor, product, version

    # web_server_proxy (nginx, Microsoft, Apache) -> application_framework (Apache, Microsoft IIS, nginx)

    # Layer order: web_server_proxy (nginx, Microsoft, Apache) comes before application_framework

    assert idents1[0]["product"] == "nginx"

    assert idents1[1]["product"] == "Microsoft IIS"

    assert idents1[2]["product"] == "Apache"



def test_malformed_version_rejected():

    from api.scanner.technology_identity import extract_technology_identities

    

    findings = [

        {"rule_id": "info_disclosure_server_banner", "module": "Discovery", "evidence": "nginx/1.24.0:malformed", "confidence": "Medium"},

    ]

    idents = extract_technology_identities(findings)

    

    # Malformed version with invalid characters will be filtered out

    assert len(idents) == 0



def test_empty_version_no_cpe():

    from api.scanner.technology_identity import extract_technology_identities

    

    findings = [

        {"rule_id": "technology_js_frameworks_detected", "module": "JS", "evidence": "React", "confidence": "Medium"},

    ]

    idents = extract_technology_identities(findings)

    

    assert idents[0]["cpe_candidate"] is None

    assert idents[0]["cpe_authority"] == "CANDIDATE"



def test_multiple_sources_merge_deterministic():

    from api.scanner.technology_identity import extract_technology_identities

    

    findings = [

        {"rule_id": "info_disclosure_server_banner", "module": "Discovery", "evidence": "nginx/1.24.0", "confidence": "Medium"},

        {"rule_id": "info_disclosure_server_banner", "module": "Discovery", "evidence": "nginx/1.24.0", "confidence": "Low"},

    ]

    idents = extract_technology_identities(findings)

    

    assert len(idents) == 1

    assert idents[0]["cpe_authority"] == "AUTHORITATIVE"

    assert len(idents[0]["sources"]) == 2

    # Sources should be merged and sorted deterministically

    assert idents[0]["sources"][0]["source_type"] == "server_header"

    assert idents[0]["sources"][1]["source_type"] == "server_header"



def test_backward_compat_cpe_field():

    from api.scanner.technology_identity import extract_technology_identities

    

    findings = [

        {"rule_id": "info_disclosure_server_banner", "module": "Discovery", "evidence": "nginx/1.24.0", "confidence": "Medium"},

    ]

    idents = extract_technology_identities(findings)

    

    assert "cpe" in idents[0]

    assert idents[0]["cpe"] == idents[0]["cpe_candidate"]

    assert idents[0]["cpe"] == "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"



def test_cve_list_initialized():

    from api.scanner.technology_identity import extract_technology_identities

    

    findings = [

        {"rule_id": "info_disclosure_server_banner", "module": "Discovery", "evidence": "nginx/1.24.0", "confidence": "Medium"},

    ]

    idents = extract_technology_identities(findings)

    

    assert idents[0]["cves"] == []



def test_version_precision_affects_cpe():

    from api.scanner.technology_identity import extract_technology_identities

    

    findings_obs = [

        {"rule_id": "info_disclosure_server_banner", "module": "Discovery", "evidence": "nginx/1.24.0", "confidence": "Medium"},

    ]

    idents_obs = extract_technology_identities(findings_obs)

    

    findings_unknown = [

        {"rule_id": "technology_detected", "module": "Headers", "evidence": {"product": "nginx", "version": "1.24.0", "source": "js_asset"}, "confidence": "Medium"},

    ]

    idents_unknown = extract_technology_identities(findings_unknown)

    

    assert idents_obs[0]["cpe_authority"] == "AUTHORITATIVE"

    assert idents_unknown[0]["cpe_authority"] == "CANDIDATE"


