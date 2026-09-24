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


from urllib.parse import urlparse, urlunparse

def normalize_for_compare(url: str) -> str:
    if not url: return url
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path
        if path == '/':
            path = ''
        return urlunparse((scheme, netloc, path, parsed.params, parsed.query, ''))
    except Exception:
        return url

def compare_reports(old_scan: Dict[str, Any], new_scan: Dict[str, Any]) -> Dict[str, Any]:
    if normalize_for_compare(old_scan.get("target_url", "")) != normalize_for_compare(new_scan.get("target_url", "")):
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

    from api.scanner.priority import calculate_cve_priority
    old_tech = old_data.get("technology_identities") or []
    new_tech = new_data.get("technology_identities") or []

    tech_added = []
    tech_removed = []
    tech_version_changed = []
    new_cves = []

    intelligence_acquired = []
    intelligence_recovered = []
    intelligence_lost = []
    cve_no_longer_matched = []
    cve_removed = []
    cve_priority_changed = []

    old_tech_map = {(t.get("layer"), t.get("product")): t for t in old_tech}
    new_tech_map = {(t.get("layer"), t.get("product")): t for t in new_tech}

    for key, new_t in new_tech_map.items():
        if key not in old_tech_map:
            tech_added.append(new_t)
        else:
            old_t = old_tech_map[key]
            if new_t.get("version") and old_t.get("version") and new_t.get("version") != old_t.get("version"):
                tech_version_changed.append({
                    "product": new_t.get("product"),
                    "old_version": old_t.get("version"),
                    "new_version": new_t.get("version")
                })

            old_state = old_t.get("vulnerability_state", "NOT_EVALUATED")
            new_state = new_t.get("vulnerability_state", "NOT_EVALUATED")

            if old_state in ("NOT_EVALUATED", "UNAVAILABLE") and new_state in ("MATCHED", "NO_MATCH"):
                event_type = "intelligence_acquired" if old_state == "NOT_EVALUATED" else "intelligence_recovered"
                event_list = intelligence_acquired if old_state == "NOT_EVALUATED" else intelligence_recovered
                event_list.append({"product": new_t.get("product"), "old_state": old_state, "new_state": new_state})
            elif old_state == "MATCHED" and new_state in ("NOT_EVALUATED", "UNAVAILABLE"):
                intelligence_lost.append({"product": new_t.get("product"), "old_state": old_state, "new_state": new_state})
            elif old_state == "NO_MATCH" and new_state == "MATCHED":
                intelligence_acquired.append({"product": new_t.get("product"), "old_state": old_state, "new_state": new_state})
            elif old_state == "MATCHED" and new_state == "NO_MATCH":
                for old_c in (old_t.get("cves") or []):
                    cve_no_longer_matched.append({
                        "product": new_t.get("product"),
                        "cve_id": old_c.get("id"),
                        "severity": old_c.get("severity"),
                        "summary": old_c.get("summary")
                    })
            elif old_state == "MATCHED" and new_state == "MATCHED":
                old_cves_list = old_t.get("cves") or []
                new_cves_list = new_t.get("cves") or []

                old_cve_map = {c.get("id"): c for c in old_cves_list}
                new_cve_map = {c.get("id"): c for c in new_cves_list}

                for c_id, new_c in new_cve_map.items():
                    if c_id not in old_cve_map:
                        new_cves.append({
                            "product": new_t.get("product"),
                            "cve_id": c_id,
                            "severity": new_c.get("severity"),
                            "summary": new_c.get("summary")
                        })
                    else:
                        old_c = old_cve_map[c_id]
                        old_prio = calculate_cve_priority(old_t, old_c)
                        new_prio = calculate_cve_priority(new_t, new_c)
                        if old_prio != new_prio:
                            cve_priority_changed.append({
                                "product": new_t.get("product"),
                                "cve_id": c_id,
                                "old_priority": old_prio,
                                "new_priority": new_prio,
                                "severity": new_c.get("severity"),
                                "summary": new_c.get("summary")
                            })

                for c_id, old_c in old_cve_map.items():
                    if c_id not in new_cve_map:
                        cve_removed.append({
                            "product": new_t.get("product"),
                            "cve_id": c_id,
                            "severity": old_c.get("severity"),
                            "summary": old_c.get("summary")
                        })

    for key, old_t in old_tech_map.items():
        if key not in new_tech_map:
            tech_removed.append(old_t)

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
        "unchanged": unchanged,
        "tech_added": tech_added,
        "tech_removed": tech_removed,
        "tech_version_changed": tech_version_changed,
        "new_cves": new_cves,
        "intelligence_acquired": intelligence_acquired,
        "intelligence_recovered": intelligence_recovered,
        "intelligence_lost": intelligence_lost,
        "cve_no_longer_matched": cve_no_longer_matched,
        "cve_removed": cve_removed,
        "cve_priority_changed": cve_priority_changed
    }
