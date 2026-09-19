import os
import logging
from datetime import datetime, timezone
import requests
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)
worker_router = APIRouter()

QSTASH_CURRENT_SIGNING_KEY = os.environ.get("QSTASH_CURRENT_SIGNING_KEY")
QSTASH_NEXT_SIGNING_KEY = os.environ.get("QSTASH_NEXT_SIGNING_KEY")
SUPABASE_URL = os.environ.get("VITE_SUPABASE_URL") or os.environ.get("SUPABASE_URL")
SUPABASE_SECRET_KEY = os.environ.get("SUPABASE_SECRET_KEY")

async def verify_qstash_signature(request: Request):
    try:
        from qstash import Receiver
    except ImportError:
        logger.error("qstash package not installed")
        raise HTTPException(status_code=500, detail="QStash not installed")

    if not Receiver or not QSTASH_CURRENT_SIGNING_KEY or not QSTASH_NEXT_SIGNING_KEY:
        logger.error("QStash signature keys not configured")
        raise HTTPException(status_code=500, detail="QStash keys missing in production")

    signature = request.headers.get("Upstash-Signature")
    if not signature:
        logger.error("Missing Upstash-Signature")
        raise HTTPException(status_code=401, detail="Missing signature")

    body = await request.body()

    receiver = Receiver(
        current_signing_key=QSTASH_CURRENT_SIGNING_KEY,
        next_signing_key=QSTASH_NEXT_SIGNING_KEY
    )

    try:
        receiver.verify(
            body=body.decode("utf-8"),
            signature=signature,
            url=str(request.url)
        )
    except Exception as e:
        logger.error(f"QStash signature verification failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid signature")

    return True

@worker_router.post("/enrich-cve")
async def enrich_cve_worker(request: Request, verified: bool = Depends(verify_qstash_signature)):
    import time
    import copy
    start_time = time.time()
    BUDGET = 45.0

    def remaining_time(max_val=10.0):
        return max(1.0, min(max_val, BUDGET - (time.time() - start_time)))

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON"})

    scan_id = body.get("scan_id")
    if not scan_id:
        return JSONResponse(status_code=400, content={"error": "Missing scan_id"})

    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        logger.error("Supabase not configured")
        return JSONResponse(status_code=500, content={"error": "Supabase not configured"})

    headers = {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }

    retried_count = int(request.headers.get("Upstash-Retried", "0"))
    is_last_retry = retried_count >= 3

    # 1. Fetch Scan
    scan_resp = requests.get(f"{SUPABASE_URL.rstrip('/')}/rest/v1/scans?id=eq.{scan_id}", headers=headers, timeout=remaining_time())
    if scan_resp.status_code != 200 or not scan_resp.json():
        logger.warning(f"Scan {scan_id} not found or deleted")
        return JSONResponse(status_code=200, content={"status": "skipped", "reason": "scan_not_found"})

    scan_row = scan_resp.json()[0]
    report_data = scan_row.get("report_data", {})

    curr_status = report_data.get("cve_enrichment_status")
    if curr_status in ("COMPLETED", "FAILED"):
        return JSONResponse(status_code=200, content={"status": "skipped", "reason": "already_terminal"})

    # Claim idempotently: QUEUED -> RUNNING, NOT_REQUESTED -> RUNNING, or RUNNING(expired) -> RUNNING
    claim_res = requests.post(
        f"{SUPABASE_URL.rstrip('/')}/rest/v1/rpc/atomic_update_cve_status",
        headers=headers,
        json={"p_scan_id": scan_id, "p_expected_status": "QUEUED", "p_new_status": "RUNNING", "p_lease_duration_sec": 55},
        timeout=remaining_time()
    )
    if claim_res.status_code != 200 or claim_res.json() is not True:
        # Race: worker arrived before main request upgraded NOT_REQUESTED -> QUEUED
        claim_res = requests.post(
            f"{SUPABASE_URL.rstrip('/')}/rest/v1/rpc/atomic_update_cve_status",
            headers=headers,
            json={"p_scan_id": scan_id, "p_expected_status": "NOT_REQUESTED", "p_new_status": "RUNNING", "p_lease_duration_sec": 55},
            timeout=remaining_time()
        )
        if claim_res.status_code != 200 or claim_res.json() is not True:
            # If we couldn't claim it, another worker holds an active lease or it's a network error.
            # Returning 503 ensures QStash will retry.
            return JSONResponse(status_code=503, content={"error": "lease_active_or_error", "status": 503})

    identities = report_data.get("technology_identities", [])
    if not identities:
        comp_res = requests.post(
            f"{SUPABASE_URL.rstrip('/')}/rest/v1/rpc/atomic_update_cve_status",
            headers=headers,
            json={"p_scan_id": scan_id, "p_expected_status": "RUNNING", "p_new_status": "COMPLETED"},
            timeout=remaining_time()
        )
        if comp_res.status_code != 200 or comp_res.json() is not True:
            logger.error(f"Failed to persist COMPLETED state for {scan_id}")
            return JSONResponse(status_code=500, content={"error": "persistence_failed"})
        return JSONResponse(status_code=200, content={"status": "completed", "reason": "no_identities"})

    def release_worker_state(reason_str):
        if is_last_retry:
            res = requests.post(
                f"{SUPABASE_URL.rstrip('/')}/rest/v1/rpc/atomic_update_cve_status",
                headers=headers,
                json={"p_scan_id": scan_id, "p_expected_status": "RUNNING", "p_new_status": "FAILED"},
                timeout=max(1.0, remaining_time())
            )
            if res.status_code != 200 or res.json() is not True:
                logger.error(f"Failed to persist FAILED state for {scan_id}")
                return JSONResponse(status_code=500, content={"error": "persistence_failed"})
            return JSONResponse(status_code=200, content={"status": "failed", "reason": f"{reason_str}_exhausted"})
        else:
            res = requests.post(
                f"{SUPABASE_URL.rstrip('/')}/rest/v1/rpc/atomic_update_cve_status",
                headers=headers,
                json={"p_scan_id": scan_id, "p_expected_status": "RUNNING", "p_new_status": "QUEUED"},
                timeout=max(1.0, remaining_time())
            )
            if res.status_code != 200 or res.json() is not True:
                logger.error(f"Failed to persist QUEUED (release) state for {scan_id}")
                return JSONResponse(status_code=500, content={"error": "persistence_failed"})
            return JSONResponse(status_code=503, content={"error": f"{reason_str}, retry", "status": 503})

    def _get_match_metadata(identity: dict) -> tuple:
        match_confidence = identity.get("cpe_match_confidence", "LOW")
        rationale_code = None
        rationale_text = None

        sources = identity.get("sources", [])
        if any(s.get("source_type") in ("server_header", "x_powered_by") for s in sources):
            match_confidence = "MEDIUM"
            rationale_code = "SPOOFABLE_SOURCE"
            rationale_text = "Match is based on a spoofable HTTP header."

        return match_confidence, rationale_code, rationale_text

    try:
        identity_parsed_cves = []
        cpe_to_parsed_cves = {}
        cpe_needs_cache_save = {}
        has_terminal_intelligence_failure = False

        import time
        import copy
        from datetime import datetime, timezone
        for identity in identities:
            if time.time() - start_time > BUDGET:
                logger.warning(f"Time budget exceeded for scan {scan_id}")
                return release_worker_state("budget")

            cpe = identity.get("cpe_candidate") or identity.get("cpe")
            if identity.get("vulnerability_state") == "NOT_EVALUATED" and identity.get("vulnerability_state_reason") in ("INSUFFICIENT_VERSION", "NO_CPE_MAPPING"):
                identity_parsed_cves.append((identity, None))
                continue

            if not cpe or identity.get("vulnerability_state") in ("MATCHED", "NO_MATCH", "UNAVAILABLE"):
                identity_parsed_cves.append((identity, None))
                continue

            cache_key = f"{cpe}#v4"
            if cache_key in cpe_to_parsed_cves:
                identity_parsed_cves.append((identity, cpe_to_parsed_cves[cache_key]))
                continue

            cached_cves = None
            try:
                now_utc_str = datetime.now(timezone.utc).isoformat()
                cache_resp = requests.get(
                    f"{SUPABASE_URL.rstrip('/')}/rest/v1/cpe_cve_cache?cpe=eq.{requests.utils.quote(cache_key)}&expires_at=gt.{requests.utils.quote(now_utc_str)}",
                    headers=headers,
                    timeout=remaining_time(10.0)
                )
                if cache_resp.status_code == 200:
                    cache_data = cache_resp.json()
                    if cache_data and len(cache_data) > 0:
                        cached_cves = cache_data[0].get("cves_json")
            except Exception:
                pass

            if cached_cves is not None:
                cpe_to_parsed_cves[cache_key] = cached_cves
                cpe_needs_cache_save[cache_key] = False
                identity_parsed_cves.append((identity, cached_cves))
                continue

            try:
                nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={requests.utils.quote(cpe)}&isVulnerable"
                resp = requests.get(nvd_url, timeout=remaining_time(15.0))

                if resp.status_code in (403, 429) or resp.status_code >= 500:
                    if not is_last_retry:
                        return release_worker_state(f"nvd_transient")
                    else:
                        identity["vulnerability_state"] = "UNAVAILABLE"
                        identity["vulnerability_state_reason"] = "INTELLIGENCE_UNAVAILABLE"
                        identity["cves"] = []
                        identity_parsed_cves.append((identity, None))
                        continue

                if resp.status_code == 200:
                    data = resp.json()
                    parsed_cves = []
                    vulnerabilities = data.get("vulnerabilities", [])
                    for vuln_item in vulnerabilities:
                        if len(parsed_cves) >= 5:
                            break
                        cve_data = vuln_item.get("cve", {})
                        cve_id = cve_data.get("id")
                        if not cve_id: continue

                        summary = "No description provided."
                        for desc in cve_data.get("descriptions", []):
                            if desc.get("lang") == "en":
                                summary = desc.get("value")
                                break

                        # Phase 5B: CVSS, CWE, Metadata
                        cvss_assessments = []
                        cwes = []
                        metadata = {
                            "published_at": cve_data.get("published"),
                            "last_modified_at": cve_data.get("lastModified"),
                            "fetched_at": datetime.now(timezone.utc).isoformat(),
                            "source_identifier": cve_data.get("sourceIdentifier")
                        }

                        try:
                            metrics = cve_data.get("metrics", {})
                            for version_key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                                if version_key in metrics:
                                    for metric in metrics[version_key]:
                                        try:
                                            cvss_data = metric.get("cvssData", {})
                                            base_severity = cvss_data.get("baseSeverity")
                                            if version_key == "cvssMetricV2" and not base_severity:
                                                base_severity = metric.get("baseSeverity")

                                            base_score = cvss_data.get("baseScore")
                                            if base_score is None and version_key == "cvssMetricV2":
                                                base_score = metric.get("baseScore")
                                            if base_score is not None:
                                                cvss_assessments.append({
                                                    "version": cvss_data.get("version"),
                                                    "source": metric.get("source"),
                                                    "type": metric.get("type"),
                                                    "base_score": base_score,
                                                    "base_severity": base_severity,
                                                    "vector_string": cvss_data.get("vectorString")
                                                })
                                        except Exception:
                                            pass
                        except Exception:
                            pass

                        try:
                            for weakness in cve_data.get("weaknesses", []):
                                try:
                                    cwe_source = weakness.get("source")
                                    cwe_type = weakness.get("type")
                                    for desc in weakness.get("description", []):
                                        cwe_id = desc.get("value")
                                        if cwe_id:
                                            cwes.append({
                                                "cwe_id": cwe_id,
                                                "source": cwe_source,
                                                "type": cwe_type,
                                                "name": None
                                            })
                                except Exception:
                                    pass
                        except Exception:
                            pass

                        kev = None
                        if isinstance(cve_data, dict) and cve_data.get("cisaExploitAdd"):
                            kev = {
                                "added": cve_data.get("cisaExploitAdd"),
                                "due": cve_data.get("cisaActionDue"),
                                "action": cve_data.get("cisaRequiredAction"),
                                "name": cve_data.get("cisaVulnerabilityName")
                            }

                        ssvc = None
                        try:
                            if isinstance(metrics, dict) and "ssvcV203" in metrics:
                                ssvc_list = metrics["ssvcV203"]
                                cisa_records = []
                                if isinstance(ssvc_list, list):
                                    CISA_ADP_ORG_ID = "134c704f-9b21-4f2e-91b3-4a467353bcc0"
                                    for s in ssvc_list:
                                        if isinstance(s, dict) and str(s.get("source", "")).strip().lower() == CISA_ADP_ORG_ID:
                                            cisa_records.append(s)

                                if cisa_records:
                                    import json as _json
                                    def ssvc_sort_key(record):
                                        if not isinstance(record, dict):
                                            return ("", "", "", "", "")
                                        data = record.get("ssvcData", {})
                                        if not isinstance(data, dict):
                                            return ("", "", "", "", "")
                                        ts = str(data.get("timestamp", ""))
                                        ver = str(data.get("version", ""))
                                        role = str(data.get("role", ""))
                                        rec_id = str(data.get("id", ""))
                                        canonical = _json.dumps(record, sort_keys=True, default=str)
                                        return (ts, ver, role, rec_id, canonical)

                                    cisa_records.sort(key=ssvc_sort_key, reverse=True)
                                    cisa_ssvc = cisa_records[0]

                                    ssvc_data = cisa_ssvc.get("ssvcData", {})
                                    options_list = ssvc_data.get("options", []) if isinstance(ssvc_data, dict) else []
                                    options_dict = {}
                                    import re as _re
                                    def _to_lower_camel(k):
                                        parts = [p for p in _re.split(r'[\s\-_]+', str(k).strip()) if p]
                                        if not parts:
                                            return ""
                                        if len(parts) == 1:
                                            return parts[0][:1].lower() + parts[0][1:]
                                        return parts[0].lower() + "".join(p.capitalize() for p in parts[1:])

                                    if isinstance(options_list, list):
                                        for opt in options_list:
                                            if isinstance(opt, dict):
                                                for k, v in opt.items():
                                                    if isinstance(k, str) and k.strip():
                                                        options_dict[_to_lower_camel(k)] = str(v)
                                    elif isinstance(options_list, dict):
                                        for k, v in options_list.items():
                                            if isinstance(k, str) and k.strip():
                                                options_dict[_to_lower_camel(k)] = str(v)

                                    if isinstance(ssvc_data, dict):
                                        ssvc = {
                                            "source": cisa_ssvc.get("source"),
                                            "role": ssvc_data.get("role"),
                                            "version": ssvc_data.get("version"),
                                            "timestamp": ssvc_data.get("timestamp"),
                                            "options": options_dict
                                        }
                        except Exception:
                            pass

                        cve_obj = {
                            "id": cve_id,
                            "summary": summary,
                            "cvss_assessments": cvss_assessments,
                            "cwes": cwes,
                            "metadata": metadata,
                            "epss": None
                        }
                        if kev:
                            cve_obj["kev"] = kev
                        if ssvc:
                            cve_obj["ssvc"] = ssvc

                        parsed_cves.append(cve_obj)

                    cpe_to_parsed_cves[cache_key] = parsed_cves
                    cpe_needs_cache_save[cache_key] = True
                    identity_parsed_cves.append((identity, parsed_cves))
                else:
                    has_terminal_intelligence_failure = True
                    identity["vulnerability_state"] = "UNAVAILABLE"
                    identity["vulnerability_state_reason"] = "INTELLIGENCE_UNAVAILABLE"
                    identity["cves"] = []
                    identity_parsed_cves.append((identity, None))
                    continue

            except (requests.exceptions.Timeout, Exception) as e:
                if not is_last_retry:
                    return release_worker_state("nvd_timeout" if isinstance(e, requests.exceptions.Timeout) else "nvd_exception")
                else:
                    has_terminal_intelligence_failure = True
                    identity["vulnerability_state"] = "UNAVAILABLE"
                    identity["vulnerability_state_reason"] = "INTELLIGENCE_UNAVAILABLE"
                    identity["cves"] = []
                    identity_parsed_cves.append((identity, None))
                    continue

        # Pass 2: EPSS Fetch globally across all new CVEs
        unique_cves_for_epss = set()
        for cache_key, needs_save in cpe_needs_cache_save.items():
            if needs_save:
                for c in cpe_to_parsed_cves[cache_key]:
                    unique_cves_for_epss.add(c["id"])

        unique_cves_for_epss = list(unique_cves_for_epss)
        epss_terminal_failure = False
        epss_map = {}

        if unique_cves_for_epss:
            MAX_CVE_QUERY_CHARS = 1800
            batches = []
            current_batch = []
            current_len = 0
            for c_id in unique_cves_for_epss:
                added_len = len(c_id) if not current_batch else len(c_id) + 1
                if current_len + added_len > MAX_CVE_QUERY_CHARS:
                    batches.append(current_batch)
                    current_batch = [c_id]
                    current_len = len(c_id)
                else:
                    current_batch.append(c_id)
                    current_len += added_len
            if current_batch:
                batches.append(current_batch)

            for batch in batches:
                try:
                    epss_url = f"https://api.first.org/data/v1/epss?cve={','.join(batch)}"
                    epss_resp = requests.get(epss_url, timeout=remaining_time(5.0))
                    if epss_resp.status_code == 200:
                        data = epss_resp.json().get("data", [])
                        for item in data:
                            c_id = item.get("cve")
                            if not c_id or c_id in epss_map:
                                continue
                            try:
                                score_raw = item.get("epss")
                                perc_raw = item.get("percentile")
                                if isinstance(score_raw, bool) or isinstance(perc_raw, bool) or score_raw is None or perc_raw is None:
                                    continue

                                score_val = float(score_raw)
                                perc_val = float(perc_raw)
                                import math
                                if math.isnan(score_val) or math.isinf(score_val) or math.isnan(perc_val) or math.isinf(perc_val):
                                    continue
                                if not (0.0 <= score_val <= 1.0) or not (0.0 <= perc_val <= 1.0):
                                    continue

                                score_date = item.get("date") or item.get("created")
                                if not score_date or not isinstance(score_date, str):
                                    continue

                                import re
                                if not re.match(r"^\d{4}-\d{2}-\d{2}$", score_date):
                                    continue

                                try:
                                    datetime.strptime(score_date, "%Y-%m-%d")
                                except ValueError:
                                    continue

                                epss_map[c_id] = {
                                    "score": score_val,
                                    "percentile": perc_val,
                                    "score_date": score_date,
                                    "source": "FIRST",
                                    "fetched_at": datetime.now(timezone.utc).isoformat()
                                }
                            except Exception:
                                pass
                    else:
                        if not is_last_retry:
                            return release_worker_state("EPSS_TRANSIENT")
                        else:
                            epss_terminal_failure = True
                            break
                except Exception as e:
                    if not is_last_retry:
                        return release_worker_state("EPSS_TRANSIENT")
                    else:
                        epss_terminal_failure = True
                        break

        from datetime import timedelta
        import copy
        now = datetime.now(timezone.utc)
        expires = (now + timedelta(days=1)).isoformat()

        for cache_key, parsed_cves in cpe_to_parsed_cves.items():
            if cpe_needs_cache_save[cache_key]:
                for c in parsed_cves:
                    c["epss"] = epss_map.get(c["id"])

                if not epss_terminal_failure:
                    cache_payload = {
                        "cpe": cache_key,
                        "cves_json": parsed_cves,
                        "fetched_at": now.isoformat(),
                        "expires_at": expires,
                        "updated_at": now.isoformat()
                    }
                    try:
                        requests.post(
                            f"{SUPABASE_URL.rstrip('/')}/rest/v1/cpe_cve_cache",
                            headers={**headers, "Prefer": "resolution=merge-duplicates"},
                            json=cache_payload,
                            timeout=remaining_time(5.0)
                        )
                    except Exception:
                        pass

        enriched_identities = []
        for identity, parsed_cves in identity_parsed_cves:
            if parsed_cves is not None:
                cves_copy = copy.deepcopy(parsed_cves)
                match_confidence, rationale_code, rationale_text = _get_match_metadata(identity)
                for c in cves_copy:
                    c["match_confidence"] = match_confidence
                    c["rationale_code"] = rationale_code
                    c["rationale_text"] = rationale_text

                identity["cves"] = cves_copy
                identity["vulnerability_state"] = "MATCHED" if cves_copy else "NO_MATCH"
                identity["vulnerability_state_reason"] = None if cves_copy else "NO_KNOWN_NVD_MATCH"

            enriched_identities.append(identity)

        save_res = requests.post(
            f"{SUPABASE_URL.rstrip('/')}/rest/v1/rpc/atomic_save_enriched_identities",
            headers=headers,
            json={"p_scan_id": scan_id, "p_expected_status": "RUNNING", "p_status": "FAILED" if has_terminal_intelligence_failure else "COMPLETED", "p_identities": enriched_identities},
            timeout=remaining_time(10.0)
        )
        if save_res.status_code != 200 or save_res.json() is not True:
            logger.error(f"Failed to persist enriched identities and COMPLETED state for {scan_id}")
            return JSONResponse(status_code=500, content={"error": "persistence_failed"})
        return JSONResponse(status_code=200, content={"status": "failed" if has_terminal_intelligence_failure else "completed"})

    except Exception as e:
        logger.error(f"Enrichment worker failed: {e}")
        if is_last_retry:
            try:
                res = requests.post(
                    f"{SUPABASE_URL.rstrip('/')}/rest/v1/rpc/atomic_update_cve_status",
                    headers=headers,
                    json={"p_scan_id": scan_id, "p_expected_status": "RUNNING", "p_status": "FAILED"}
                )
                if res.status_code == 200 and res.json() is True:
                    return JSONResponse(status_code=200, content={"status": "failed"})
            except Exception as final_e:
                logger.error(f"Failed to set status to FAILED: {final_e}")

        try:
            return release_worker_state("worker_exception")
        except Exception as inner_e:
            logger.error(f"Failed to release worker state after exception: {inner_e}")
            return JSONResponse(status_code=500, content={"error": "Internal error", "status": 500})
