import json
from collections import defaultdict
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

def _get_identity(f: dict) -> tuple:
    name = str(f.get("name", "")).strip()
    module = str(f.get("module", "")).strip()
    if module == "None":
        module = ""
    return (module, name)

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

    old_groups = defaultdict(list)
    for f in old_findings:
        old_groups[_get_identity(f)].append(f)

    new_groups = defaultdict(list)
    for f in new_findings:
        new_groups[_get_identity(f)].append(f)

    # Safe cross-version legacy matching for missing modules
    old_moduleless = [k for k in list(old_groups.keys()) if k[0] == ""]
    for k in old_moduleless:
        if k in new_groups:
            continue
        candidates = [nk for nk in new_groups.keys() if nk[1] == k[1] and nk[0] != ""]
        if len(candidates) == 1:
            target_key = candidates[0]
            old_groups[target_key].extend(old_groups[k])
            del old_groups[k]

    new_moduleless = [k for k in list(new_groups.keys()) if k[0] == ""]
    for k in new_moduleless:
        if k in old_groups:
            continue
        candidates = [ok for ok in old_groups.keys() if ok[1] == k[1] and ok[0] != ""]
        if len(candidates) == 1:
            target_key = candidates[0]
            new_groups[target_key].extend(new_groups[k])
            del new_groups[k]

    added = []
    removed = []
    improved = []
    regressed = []
    unchanged = []

    # Sort to ensure deterministic output
    all_identities = sorted(list(set(old_groups.keys()) | set(new_groups.keys())))

    for identity in all_identities:
        old_list = old_groups[identity]
        new_list = new_groups[identity]

        unmatched_old = []
        used_new_indices = set()

        # 1. Exact severity pairing
        for old_f in old_list:
            old_sev = _get_severity_weight(old_f.get("severity"))
            matched = False
            for i, new_f in enumerate(new_list):
                if i not in used_new_indices:
                    new_sev = _get_severity_weight(new_f.get("severity"))
                    if old_sev == new_sev:
                        unchanged.append(new_f)
                        used_new_indices.add(i)
                        matched = True
                        break
            if not matched:
                unmatched_old.append(old_f)

        unmatched_new = [new_f for i, new_f in enumerate(new_list) if i not in used_new_indices]

        # 2. Sequential pairing for remainder (Improved/Regressed)
        match_count = min(len(unmatched_old), len(unmatched_new))
        for i in range(match_count):
            old_f = unmatched_old[i]
            new_f = unmatched_new[i]
            old_sev = _get_severity_weight(old_f.get("severity"))
            new_sev = _get_severity_weight(new_f.get("severity"))

            disp_name = new_f.get("name") or old_f.get("name", "")
            if new_sev < old_sev:
                improved.append({"name": disp_name, "old": old_f, "new": new_f})
            elif new_sev > old_sev:
                regressed.append({"name": disp_name, "old": old_f, "new": new_f})
            else:
                unchanged.append(new_f)

        # 3. Leftovers (Added/Removed)
        for i in range(match_count, len(unmatched_old)):
            removed.append(unmatched_old[i])
        for i in range(match_count, len(unmatched_new)):
            added.append(unmatched_new[i])

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
