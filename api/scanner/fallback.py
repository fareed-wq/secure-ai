def get_waf_fallback_payload(target_url: str) -> dict:
    return {
        "status": "INCOMPLETE",
        "url": target_url,
        "target": target_url,
        "score": None,
        "http_status": None,
        "latency": "Timed Out",
        "server": "Unknown",
        "ip_address": "Unknown",
        "waf_detected": False,
        "target_surface": {
            "waf_server": "Unknown",
            "waf_subtext": "Request Timed Out",
            "waf_pill": "REQUEST TIMEOUT",
            "frontend_stack": "Unknown",
            "frontend_subtext": "Could not be verified",
            "frontend_pill": "NO DATA",
            "api_surface": "Unknown",
            "api_subtext": "Target Unreachable",
            "api_pill": "NO DATA",
            "js_health": "Unknown",
            "js_subtext": "Target Unreachable",
            "js_pill": "NO DATA"
        },
        "findings": [
            {
                "id": "global_timeout",
                "name": "Scan Aborted (Global Timeout)",
                "severity": "Inconclusive",
                "category": "availability",
                "description": "The scan exceeded the maximum allowable execution time and was aborted. The target may be unresponsive, actively dropping packets, or unusually slow.",
                "evidence": {"raw": "Execution Timeout Exceeded"},
                "confidence": "High",
                "remediation": "Verify the website is online and responsive."
            }
        ],
        "severity_counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0, "Inconclusive": 1},
        "category_scores": {},
        "metadata": {"ip_address": "Unknown", "http3_supported": None, "https_enforced": None}
    }
