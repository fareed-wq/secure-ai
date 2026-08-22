from typing import Dict, Any, List

def normalize_finding(finding: Dict[str, Any]) -> str:
    """Normalize a finding to a unique string signature ignoring evidence specifics and timestamps"""
    # Use name and severity to identify a finding uniquely
    name = finding.get("name", "")
    severity = finding.get("severity", "")
    return f"{name}|{severity}"

def compare_reports(old_scan: Dict[str, Any], new_scan: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compare two scan reports and return delta.
    Assumes old_scan and new_scan are the full scan records from DB containing
    'target_url', 'scan_mode' (or inside report_data), 'score', and 'report_data'.
    """
    if old_scan.get("target_url") != new_scan.get("target_url"):
        raise ValueError("Cannot compare scans with different target URLs.")
    
    old_data = old_scan.get("report_data", {})
    new_data = new_scan.get("report_data", {})
    
    old_mode = old_data.get("scan_mode", "passive")
    new_mode = new_data.get("scan_mode", "passive")
    if old_mode != new_mode:
        raise ValueError("Cannot compare scans with different scan modes.")

    old_score = old_scan.get("score") or old_data.get("score", 0)
    new_score = new_scan.get("score") or new_data.get("score", 0)
    
    old_findings = old_data.get("findings", [])
    new_findings = new_data.get("findings", [])

    old_map = {normalize_finding(f): f for f in old_findings}
    new_map = {normalize_finding(f): f for f in new_findings}

    old_keys = set(old_map.keys())
    new_keys = set(new_map.keys())

    added_keys = new_keys - old_keys
    removed_keys = old_keys - new_keys
    unchanged_keys = old_keys & new_keys

    added = [new_map[k] for k in added_keys]
    removed = [old_map[k] for k in removed_keys]
    unchanged = [new_map[k] for k in unchanged_keys]

    score_change = new_score - old_score

    return {
        "old_score": old_score,
        "new_score": new_score,
        "score_change": score_change,
        "improved": score_change > 0,
        "regressed": score_change < 0,
        "added": added,
        "removed": removed,
        "unchanged": unchanged
    }
