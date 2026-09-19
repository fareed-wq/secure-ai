import requests
import logging
import copy

logger = logging.getLogger(__name__)

def enrich_with_cves(identities: list) -> list:
    enriched = copy.deepcopy(identities)
    
    for identity in enriched:
        identity["cves"] = []
        
        cpe = identity.get("cpe")
        precision = identity.get("version_precision")
        
        if not cpe:
            continue
            
        if precision not in ("EXACT_OBSERVED", "PARSED_OBSERVED"):
            continue
            
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}"
            resp = requests.get(url, timeout=5.0)
            
            if resp.status_code != 200:
                logger.warning(f"NVD API returned {resp.status_code} for {cpe}")
                continue
                
            data = resp.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            parsed_cves = []
            for vuln_item in vulnerabilities:
                if len(parsed_cves) >= 5:
                    break
                    
                cve_data = vuln_item.get("cve", {})
                cve_id = cve_data.get("id")
                if not cve_id:
                    continue
                    
                descriptions = cve_data.get("descriptions", [])
                summary = "No description provided."
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        summary = desc.get("value")
                        break
                        
                metrics = cve_data.get("metrics", {})
                severity = "UNKNOWN"
                
                if "cvssMetricV31" in metrics and len(metrics["cvssMetricV31"]) > 0:
                    severity = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                elif "cvssMetricV30" in metrics and len(metrics["cvssMetricV30"]) > 0:
                    severity = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                elif "cvssMetricV2" in metrics and len(metrics["cvssMetricV2"]) > 0:
                    severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")
                    
                parsed_cves.append({
                    "id": cve_id,
                    "severity": severity,
                    "summary": summary
                })
                
            identity["cves"] = parsed_cves
            
        except requests.exceptions.Timeout:
            logger.warning(f"NVD API timeout for {cpe}")
            continue
        except Exception as e:
            logger.warning(f"Failed to fetch CVEs for {cpe}: {e}")
            continue
            
    return enriched
