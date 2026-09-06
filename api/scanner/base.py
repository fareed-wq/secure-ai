import json
import re
from abc import ABC, abstractmethod
from typing import List, Optional

import requests

from api.scanner.data.dictionaries import (
    COMPLIANCE_MAP,
    IMPACT_MAP,
    REMEDIATION_SNIPPETS,
)

class ScannerModule(ABC):
    module_name = "BaseModule"
    version = "1.0.0"
    description = "Base scanner module."
    author = "Secure-AI"
    enabled = True
    timeout = 8  # Max seconds per module execution in ThreadPoolExecutor

    @abstractmethod
    def run(self, url: str, hostname: str, session: requests.Session) -> List[dict]:
        pass
    def is_spa_fallback(self, resp, homepage_len: int) -> bool:
        if not resp or not resp.text or homepage_len <= 0:
            return False
        return abs(len(resp.text) - homepage_len) < 100

    def get_header_safe(self, response, header_name: str, default: str = "") -> str:
        if not response or not hasattr(response, "headers"):
            return default
        return response.headers.get(header_name, response.headers.get(header_name.lower(), default))

    def make_finding(
        self,
        name: str,
        severity: str,
        description: str,
        evidence,
        confidence: str = "High",
        remediation: str = "N/A",
        owasp: str = "N/A",
        compliance: Optional[dict] = None,
        category: str = "information_exposure",
        cvss: Optional[str] = None,
        impact: Optional[str] = None,
        domain: str = ""
    ) -> dict:
        try:
            limit = 1000 if name in ["Exposed Secret in JS Bundle", "Source Map Leak Detected", "Verbose Error / Stack Trace Detected", "Subdomains Discovered"] else 180

            # Deep copy / serialize first to mask
            ev_str = json.dumps(evidence, default=str)
            ev_str = re.sub(r'sk_live_[a-zA-Z0-9]+', '[REDACTED_STRIPE]', ev_str)
            ev_str = re.sub(r'sk_test_[a-zA-Z0-9]+', '[REDACTED_STRIPE]', ev_str)
            ev_str = re.sub(r'Bearer\s+[a-zA-Z0-9\.\-_]+', 'Bearer [REDACTED]', ev_str)
            ev_str = re.sub(r'token=[a-zA-Z0-9\.\-_]+', 'token=[REDACTED]', ev_str)
            ev_str = re.sub(r'AKIA[0-9A-Z]{16}', '[REDACTED_AWS]', ev_str)
            ev_str = re.sub(r'sk-(?:proj-)?[a-zA-Z0-9\-_]{32,60}', '[REDACTED_OPENAI]', ev_str)
            # CI/CD and automation tokens
            ev_str = re.sub(r'(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}', '[REDACTED_GITHUB]', ev_str)
            ev_str = re.sub(r'github_pat_[a-zA-Z0-9_]{82}', '[REDACTED_GITHUB_PAT]', ev_str)
            ev_str = re.sub(r'glpat-[a-zA-Z0-9\-]{20}', '[REDACTED_GITLAB]', ev_str)
            ev_str = re.sub(r'xox[baprs]-[a-zA-Z0-9\-]+', '[REDACTED_SLACK]', ev_str)
            ev_str = re.sub(r'npm_[a-zA-Z0-9]{36}', '[REDACTED_NPM]', ev_str)
            evidence = json.loads(ev_str)

            if isinstance(evidence, str):
                evidence = {"raw": evidence[:limit]}
            elif isinstance(evidence, dict):
                if "proof_snippet" in evidence and isinstance(evidence["proof_snippet"], str):
                    evidence["proof_snippet"] = evidence["proof_snippet"][:limit]
            else:
                evidence = {"raw": str(evidence)[:limit]}

        except Exception:
            evidence = {"raw": str(evidence)[:180]}

        if compliance is None:
            compliance = COMPLIANCE_MAP.get(name, {
                "pci_dss": "6.4.1 (Public Web Application Protection)",
                "iso27001": "A.8.20 (Network Security)"
            })

        if impact is None:
            impact = IMPACT_MAP.get(
                name,
                "Potential exposure of sensitive information or risk of unauthorized actions."
            )
        if severity == "Passed":
            impact = "N/A"

        snippets = REMEDIATION_SNIPPETS.get(name, {})

        # Phase 32: CVSS V3.1 Assignment
        cvss_score = None
        cvss_severity = None

        try:
            from api.scanner.cvss_mapping import CVSS_REGISTRY, calculate_cvss31

            if cvss is None:
                cvss = CVSS_REGISTRY.get(name)

            if cvss is not None:
                cvss_score, cvss_severity = calculate_cvss31(cvss)
        except Exception:
            cvss_score = None
            cvss_severity = None

        return {
            "name": name,
            "severity": severity,
            "category": category,
            "description": description,
            "evidence": evidence,
            "confidence": confidence,
            "remediation": remediation,
            "remediation_snippets": snippets,
            "owasp": owasp,
            "compliance": compliance,
            "module": self.module_name,
            "impact": impact,
            "cvss": cvss,
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "domain": domain
        }
