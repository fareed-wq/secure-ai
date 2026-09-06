import math
from typing import Tuple

CVSS_REGISTRY = {
    "Subdomain Takeover Vulnerability (Dangling CNAME)": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "Hardcoded Third-Party Secret Key Exposed in JS Bundle": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "Sensitive Spring Boot Actuator Config Exposed": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "Exposed .env Configuration File": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "Exposed .git Repository": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "Exposed .git Configuration File": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "Exposed phpinfo() File": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "Insecure CORS Policy (Arbitrary Origin Reflection with Credentials)": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    "Insecure CORS Policy (Arbitrary Origin Reflection)": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "Insecure CORS Policy (Wildcard with Credentials)": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "Password Form Submits Over HTTP": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
    "Basic Authentication Advertised Over HTTP": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
    "Mixed Content Detected": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "Insecure Form Action (HTTP)": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"
}

METRICS_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": {"U": 0.62, "C": 0.68}, "H": {"U": 0.27, "C": 0.50}},
    "UI": {"N": 0.85, "R": 0.62},
    "S":  {"U": "U", "C": "C"},
    "C":  {"H": 0.56, "L": 0.22, "N": 0.00},
    "I":  {"H": 0.56, "L": 0.22, "N": 0.00},
    "A":  {"H": 0.56, "L": 0.22, "N": 0.00},
}

def roundup(val: float) -> float:
    # CVSS round-up mathematically correct implementation (ceiling to nearest 0.1)
    int_val = round(val * 100000)
    if int_val % 10000 == 0:
        return int_val / 100000.0
    else:
        return (math.floor(int_val / 10000) + 1) / 10.0

def calculate_cvss31(vector: str) -> Tuple[float, str]:
    if not vector.startswith("CVSS:3.1/"):
        raise ValueError("Invalid CVSS version prefix")
        
    parts_str = vector[9:].split("/")
    if len(parts_str) != 8:
        raise ValueError("Must contain exactly 8 Base metrics")
        
    parts = {}
    for p in parts_str:
        if ":" not in p:
            raise ValueError("Malformed metric")
        k, v = p.split(":", 1)
        if k in parts:
            raise ValueError(f"Duplicate metric: {k}")
        parts[k] = v
        
    for k in ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]:
        if k not in parts:
            raise ValueError(f"Missing required metric: {k}")
        if parts[k] not in METRICS_WEIGHTS[k]:
            raise ValueError(f"Invalid value for {k}: {parts[k]}")

    scope = parts["S"]
    iss = 1 - ((1 - METRICS_WEIGHTS["C"][parts["C"]]) * 
               (1 - METRICS_WEIGHTS["I"][parts["I"]]) * 
               (1 - METRICS_WEIGHTS["A"][parts["A"]]))
               
    impact = 0.0
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        
    pr = METRICS_WEIGHTS["PR"][parts["PR"]]
    if isinstance(pr, dict):
        pr = pr[scope]
        
    exploitability = 8.22 * METRICS_WEIGHTS["AV"][parts["AV"]] * METRICS_WEIGHTS["AC"][parts["AC"]] * pr * METRICS_WEIGHTS["UI"][parts["UI"]]
    
    if impact <= 0:
        return 0.0, "None"
        
    if scope == "U":
        score = roundup(min(impact + exploitability, 10.0))
    else:
        score = roundup(min(1.08 * (impact + exploitability), 10.0))
        
    if score == 0.0: sev = "None"
    elif score < 4.0: sev = "Low"
    elif score < 7.0: sev = "Medium"
    elif score < 9.0: sev = "High"
    else: sev = "Critical"
    
    return score, sev
