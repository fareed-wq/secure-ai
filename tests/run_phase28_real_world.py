import sys
import logging
from pprint import pprint
from api.scanner.orchestrator import scan_url

logging.basicConfig(level=logging.INFO)

def run_real_world(target="https://example.com"):
    print(f"Running Phase 28 real-world validation against {target}...")
    try:
        report = scan_url(target)
        
        print("\n=== SCAN COMPLETE ===")
        print(f"Target: {report.get('url')}")
        print(f"Score: {report.get('score')}")
        print("\nFindings:")
        
        for finding in report.get("findings", []):
            if finding.get("category") in ["domain_email", "dns_security", "technology_detection", "information_exposure"]:
                print(f" - [{finding.get('severity')}] {finding.get('name')}")
                if "evidence" in finding and isinstance(finding["evidence"], dict):
                    print(f"     Evidence: {finding['evidence'].get('raw', '')[:100]}")
                elif "evidence" in finding:
                    print(f"     Evidence: {str(finding['evidence'])[:100]}")
                    
        print("\n=== SUMMARY ===")
        print(f"Severity counts: {report.get('severity_counts')}")
    except Exception as e:
        print(f"Scan failed: {e}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    run_real_world(target)
