import pytest
from api.scanner.cvss_mapping import CVSS_REGISTRY, calculate_cvss40
from api.scanner.base import ScannerModule

def test_cvss_calculator_basic():
    # FIRST CVSS v4.0 reference vectors (sourced from FIRST official examples)
    # Maximum severity reference
    score, sev = calculate_cvss40("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
    assert score == 10.0
    assert sev == "Critical"

    # Minimum severity reference
    score, sev = calculate_cvss40("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N")
    assert score == 0.0
    assert sev == "None"

def test_cvss_calculator_registry():
    # Test all 9 approved vectors from the registry
    assert len(CVSS_REGISTRY) == 9

    expected_scores = {
        "Subdomain Takeover Vulnerability (Dangling CNAME)": (8.7, "High"),
        "Hardcoded Third-Party Secret Key Exposed in JS Bundle": (8.7, "High"),
        "Sensitive Spring Boot Actuator Config Exposed": (8.7, "High"),
        "Exposed .env Configuration File": (8.7, "High"),
        "Exposed phpinfo() File": (6.9, "Medium"),
        "Password Form Submits Over HTTP": (6.0, "Medium"),
        "Basic Authentication Advertised Over HTTP": (6.0, "Medium"),
        "Insecure Form Action (HTTP)": (2.3, "Low"),
        "Insecure CORS Policy (Arbitrary Origin Reflection with Credentials)": (7.1, "High")
    }

    for name, vector in CVSS_REGISTRY.items():
        score, sev = calculate_cvss40(vector)
        assert isinstance(score, float)
        assert sev in ["None", "Low", "Medium", "High", "Critical"]
        if name in expected_scores:
            assert score == expected_scores[name][0]
            assert sev == expected_scores[name][1]

def test_cvss_calculator_errors():
    # Invalid version
    score, sev = calculate_cvss40("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    assert score is None
    assert sev is None

    # Missing required metric (e.g. AT)
    score, sev = calculate_cvss40("CVSS:4.0/AV:N/AC:L/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N")
    assert score is None

    # Duplicate metric
    score, sev = calculate_cvss40("CVSS:4.0/AV:N/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N")
    assert score is None

    # Malformed vector
    score, sev = calculate_cvss40("not a vector")
    assert score is None

class DummyScanner(ScannerModule):
    def __init__(self, url):
        self.url = url
        self.module_name = "dummy"

    def run(self):
        pass

def test_registry_behavior():
    scanner = DummyScanner("http://example.com")

    # 1. Known applicable finding
    finding = scanner.make_finding(
        name="Exposed .env Configuration File",
        severity="High",
        category="information_exposure",
        description="desc", evidence="ev"
    )
    assert finding["cvss"] == CVSS_REGISTRY["Exposed .env Configuration File"]
    assert finding["cvss_score"] == 8.7
    assert finding["cvss_severity"] == "High"

    # 2. Known removed finding (should now be None)
    finding = scanner.make_finding(
        name="Exposed .git Repository",
        severity="Medium",
        category="information_exposure",
        description="desc", evidence="ev"
    )
    assert finding["cvss"] is None
    assert finding["cvss_score"] is None
    assert finding["cvss_severity"] is None

    # 3. Another removed finding
    finding = scanner.make_finding(
        name="Mixed Content Detected",
        severity="Medium",
        category="information_exposure",
        description="desc", evidence="ev"
    )
    assert finding["cvss"] is None

    # 4. Unknown new Low finding
    finding = scanner.make_finding(
        name="Some Unknown New Low",
        severity="Low",
        category="configuration",
        description="desc", evidence="ev"
    )
    assert finding["cvss"] is None

    # 5. Unknown new Critical finding
    finding = scanner.make_finding(
        name="Some Unknown New Critical",
        severity="Critical",
        category="configuration",
        description="desc", evidence="ev"
    )
    assert finding["cvss"] is None

    # 6. Explicit override with valid 4.0
    finding = scanner.make_finding(
        name="Some Finding",
        severity="Critical",
        cvss="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
        category="configuration",
        description="desc", evidence="ev"
    )
    assert finding["cvss"] == "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
    assert finding["cvss_score"] == 0.0
    assert finding["cvss_severity"] == "None"

    # 7. Explicit override with 3.1 (backend should leave score None, frontend renders natively)
    finding = scanner.make_finding(
        name="Another Finding",
        severity="Critical",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        category="configuration",
        description="desc", evidence="ev"
    )
    assert finding["cvss"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    assert finding["cvss_score"] is None
    assert finding["cvss_severity"] is None

def test_inventory_regression_guard():
    # Exactly 9 explicitly mapped
    assert len(CVSS_REGISTRY) == 9
    for key, val in CVSS_REGISTRY.items():
        assert val.startswith("CVSS:4.0/")
        score, sev = calculate_cvss40(val)
        assert score is not None
