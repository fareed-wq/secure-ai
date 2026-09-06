from typing import Optional, Tuple

CVSS_REGISTRY = {
    "Subdomain Takeover Vulnerability (Dangling CNAME)": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    "Hardcoded Third-Party Secret Key Exposed in JS Bundle": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "Sensitive Spring Boot Actuator Config Exposed": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "Exposed .env Configuration File": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "Exposed phpinfo() File": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "Password Form Submits Over HTTP": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "Basic Authentication Advertised Over HTTP": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "Insecure Form Action (HTTP)": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "Insecure CORS Policy (Arbitrary Origin Reflection with Credentials)": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
}

try:
    from cvss import CVSS4
except ImportError:
    CVSS4 = None

def calculate_cvss40(vector: str) -> Tuple[Optional[float], Optional[str]]:
    """
    Calculates CVSS v4.0 scores using the `cvss` Python library.
    Defensively handles invalid vectors by returning (None, None).
    """
    if CVSS4 is None:
        return None, None

    if not vector.startswith("CVSS:4.0/"):
        return None, None

    try:
        c = CVSS4(vector)
        score = c.scores()[0] # base score
        sev = c.severities()[0]
        return float(score), sev
    except Exception:
        return None, None
