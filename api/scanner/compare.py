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

def _get_legacy_identity(f: dict) -> tuple:
    name = str(f.get("name", "")).strip()
    module = str(f.get("module", "")).strip()
    if module == "None":
        module = ""
    return (module, name)

def _normalize_rule_id(val):
    if not isinstance(val, str):
        return None
    val = val.strip()
    return val if val else None

def _normalize_instance_key(val):
    if not isinstance(val, str):
        return None
    val = val.strip()
    return val if val else None

def _get_stable_identity(f: dict):
    r_id = _normalize_rule_id(f.get("rule_id"))
    if not r_id:
        return None
    i_key = _normalize_instance_key(f.get("instance_key"))
    return (r_id, i_key)

def _pair_findings(old_list, new_list, unchanged, improved, regressed, unmatched_old, unmatched_new):
    local_unmatched_old = []
    used_new_indices = set()

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
            local_unmatched_old.append(old_f)

    local_unmatched_new = [new_f for i, new_f in enumerate(new_list) if i not in used_new_indices]

    match_count = min(len(local_unmatched_old), len(local_unmatched_new))
    for i in range(match_count):
        old_f = local_unmatched_old[i]
        new_f = local_unmatched_new[i]
        old_sev = _get_severity_weight(old_f.get("severity"))
        new_sev = _get_severity_weight(new_f.get("severity"))

        disp_name = new_f.get("name") or old_f.get("name", "")
        if new_sev < old_sev:
            improved.append({"name": disp_name, "old": old_f, "new": new_f})
        elif new_sev > old_sev:
            regressed.append({"name": disp_name, "old": old_f, "new": new_f})
        else:
            unchanged.append(new_f)

    for i in range(match_count, len(local_unmatched_old)):
        unmatched_old.append(local_unmatched_old[i])
    for i in range(match_count, len(local_unmatched_new)):
        unmatched_new.append(local_unmatched_new[i])

def _resolve_moduleless(groups, other_groups):
    moduleless = [k for k in list(groups.keys()) if k[0] == ""]
    for k in moduleless:
        if k in other_groups:
            continue
        candidates = [ok for ok in other_groups.keys() if ok[1] == k[1] and ok[0] != ""]
        if len(candidates) == 1:
            target_key = candidates[0]
            groups[target_key].extend(groups[k])
            del groups[k]

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

    old_stable_groups = defaultdict(list)
    old_legacy_groups = defaultdict(list)
    for f in old_findings:
        sid = _get_stable_identity(f)
        if sid:
            old_stable_groups[sid].append(f)
        else:
            old_legacy_groups[_get_legacy_identity(f)].append(f)

    new_stable_groups = defaultdict(list)
    new_legacy_groups = defaultdict(list)
    for f in new_findings:
        sid = _get_stable_identity(f)
        if sid:
            new_stable_groups[sid].append(f)
        else:
            new_legacy_groups[_get_legacy_identity(f)].append(f)

    added = []
    removed = []
    improved = []
    regressed = []
    unchanged = []

    unmatched_old_stable = []
    unmatched_new_stable = []

    # 1. STABLE <-> STABLE
    all_stable = sorted(
        list(set(old_stable_groups.keys()) | set(new_stable_groups.keys())),
        key=lambda sid: (sid[0], sid[1] is not None, sid[1] or "")
    )
    for sid in all_stable:
        _pair_findings(
            old_stable_groups[sid],
            new_stable_groups[sid],
            unchanged, improved, regressed,
            unmatched_old_stable, unmatched_new_stable
        )

    # 2. LEGACY <-> LEGACY
    _resolve_moduleless(old_legacy_groups, new_legacy_groups)
    _resolve_moduleless(new_legacy_groups, old_legacy_groups)

    unmatched_old_legacy = []
    unmatched_new_legacy = []

    all_legacy = sorted(list(set(old_legacy_groups.keys()) | set(new_legacy_groups.keys())))
    for lid in all_legacy:
        _pair_findings(
            old_legacy_groups[lid],
            new_legacy_groups[lid],
            unchanged, improved, regressed,
            unmatched_old_legacy, unmatched_new_legacy
        )

    # 3. MIXED LEFTOVERS

    unmatched_old_stable_by_leg = defaultdict(list)
    for f in unmatched_old_stable:
        unmatched_old_stable_by_leg[_get_legacy_identity(f)].append(f)

    unmatched_new_stable_by_leg = defaultdict(list)
    for f in unmatched_new_stable:
        unmatched_new_stable_by_leg[_get_legacy_identity(f)].append(f)

    old_leg_leftovers = defaultdict(list)
    for f in unmatched_old_legacy:
        old_leg_leftovers[_get_legacy_identity(f)].append(f)

    new_leg_leftovers = defaultdict(list)
    for f in unmatched_new_legacy:
        new_leg_leftovers[_get_legacy_identity(f)].append(f)

    def _do_mixed_match(leg_leftovers, stable_leftovers_by_leg, is_old_legacy):
        _resolve_moduleless(leg_leftovers, stable_leftovers_by_leg)
        _resolve_moduleless(stable_leftovers_by_leg, leg_leftovers)

        leg_unmatched_out = []
        stable_unmatched_out = []

        for lid in list(leg_leftovers.keys()):
            opposite_stable = stable_leftovers_by_leg.get(lid, [])
            if not opposite_stable:
                leg_unmatched_out.extend(leg_leftovers[lid])
                continue

            distinct_sids = set(_get_stable_identity(f) for f in opposite_stable)
            if len(distinct_sids) == 1:
                # Exactly one distinct stable identity, safe to bridge
                if is_old_legacy:
                    _pair_findings(
                        leg_leftovers[lid],
                        opposite_stable,
                        unchanged, improved, regressed,
                        leg_unmatched_out, stable_unmatched_out
                    )
                else:
                    _pair_findings(
                        opposite_stable,
                        leg_leftovers[lid],
                        unchanged, improved, regressed,
                        stable_unmatched_out, leg_unmatched_out
                    )
                del stable_leftovers_by_leg[lid]
            else:
                leg_unmatched_out.extend(leg_leftovers[lid])

        return leg_unmatched_out, stable_unmatched_out

    final_unmatched_old_legacy, final_unmatched_new_stable_from_old = _do_mixed_match(
        old_leg_leftovers,
        unmatched_new_stable_by_leg,
        is_old_legacy=True
    )

    final_unmatched_new_legacy, final_unmatched_old_stable_from_new = _do_mixed_match(
        new_leg_leftovers,
        unmatched_old_stable_by_leg,
        is_old_legacy=False
    )

    removed.extend(final_unmatched_old_legacy)
    added.extend(final_unmatched_new_legacy)

    for v in unmatched_old_stable_by_leg.values():
        removed.extend(v)
    removed.extend(final_unmatched_old_stable_from_new)

    for v in unmatched_new_stable_by_leg.values():
        added.extend(v)
    added.extend(final_unmatched_new_stable_from_old)

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
