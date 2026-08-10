import sys
import logging
import json
from api.scanner.orchestrator import scan_url

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    target = "https://example.com"
    print(f"Starting real-world passive scan of: {target}")
    
    try:
        report = scan_url(target, probe_subdomains=True)
        
        # Verify the structure has a score and findings
        if "score" not in report:
            print("ERROR: Report missing score.")
            sys.exit(1)
            
        print(f"Scan complete. Score: {report['score']}")
        print(f"Total findings: {len(report.get('findings', []))}")
        
        # Verify time budget didn't crash it
        if report['score'] == 100 and len(report.get('findings', [])) == 1 and "Aggressive WAF" in report['findings'][0].get("name", ""):
            print("Notice: Target is blocking the scanner or dead (WAF fallback triggered). This is handled gracefully.")
            sys.exit(0)
            
        print("Real-world execution successful!")
        
    except Exception as e:
        print(f"ERROR: Scan crashed with exception: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
