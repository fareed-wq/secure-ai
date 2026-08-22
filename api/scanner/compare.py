from typing import Dict, Any, List

def _normalize_mode(mode: str) -> str:
    if not mode:
        return "Unknown"
    mode = mode.lower()
    if mode == "active":
        return "Advanced"
    if mode in ("passive", "basic"):
        return "Basic"
    return "Unknown"

def _get_severity_weight(sev: str) -> int:
    sev = (sev or "").lower()
    if sev == "critical": return 4
    if sev == "high": return 3
    if sev == "medium": return 2
    if sev == "low": return 1
    if sev == "info": return 0
    return 0

def compare_reports(old_scan: Dict[str, Any], new_scan: Dict[str, Any]) -> Dict[str, Any]:
    if old_scan.get("target_url") != new_scan.get("target_url"):
        raise ValueError("Cannot compare scans with different target URLs.")
    
    old_data = old_scan.get("report_data", {})
    new_data = new_scan.get("report_data", {})
    
    old_mode = _normalize_mode(old_data.get("scan_mode"))
    new_mode = _normalize_mode(new_data.get("scan_mode"))
    
    if old_mode == "Unknown" or new_mode == "Unknown":
        raise ValueError("Cannot compare scans with unknown scan modes.")
    if old_mode != new_mode:
        raise ValueError("Cannot compare scans with different scan modes.")

    old_score = old_scan.get("score") or old_data.get("score", 0)
    new_score = new_scan.get("score") or new_data.get("score", 0)
    
    old_findings = old_data.get("findings", [])
    new_findings = new_data.get("findings", [])

    old_map = {f.get("name", ""): f for f in old_findings}
    new_map = {f.get("name", ""): f for f in new_findings}

    old_keys = set(old_map.keys())
    new_keys = set(new_map.keys())

    added_keys = new_keys - old_keys
    removed_keys = old_keys - new_keys
    common_keys = old_keys & new_keys

    added = [new_map[k] for k in added_keys]
    removed = [old_map[k] for k in removed_keys]
    
    improved = []
    regressed = []
    unchanged = []

    for k in common_keys:
        old_f = old_map[k]
        new_f = new_map[k]
        old_sev = _get_severity_weight(old_f.get("severity"))
        new_sev = _get_severity_weight(new_f.get("severity"))
        
        if new_sev < old_sev:
            improved.append({"name": k, "old": old_f, "new": new_f})
        elif new_sev > old_sev:
            regressed.append({"name": k, "old": old_f, "new": new_f})
        else:
            unchanged.append(new_f)

    score_change = new_score - old_score

    return {
        "target_url": old_scan.get("target_url"),
        "scan_mode": old_mode,
        "old_date": old_scan.get("created_at"),
        "new_date": new_scan.get("created_at"),
        "old_score": old_score,
        "new_score": new_score,
        "score_change": score_change,
        "improved": improved,
        "regressed": regressed,
        "added": added,
        "removed": removed,
        "unchanged": unchanged
    }
