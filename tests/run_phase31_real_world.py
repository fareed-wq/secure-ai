import json
import logging
from api.scanner.orchestrator import scan_url

logging.basicConfig(level=logging.INFO)

def main():
    print("Running Phase 31 Access Control Intelligence Test...")
    # Using a safe, local test domain or explicit test scenario
    # In a real run, this would be aimed at the target
    target_url = "http://example.com" # Example target
    
    try:
        result = scan_url(target_url)
        score = result.get('score', 'N/A')
        print(f"\\nScan Complete. Score: {score}")
        
        # Filter for Phase 31 specific findings
        phase31_names = [
            "Privileged Application Surface Correlated",
            "Privileged Client-Side Authorization Logic Disclosed",
            "Authorization Roles / Permissions Disclosed",
            "Privileged API Surface Discovered in Client-Side Code",
            "Versioned API Surface Discovered",
            "API Authorization Scheme Disclosed",
            "Privileged API Routes Publicly Documented",
            "Potentially Unprotected Privileged API Operation",
            "Privileged / Administrative Surface Discovered"
        ]
        
        print("\\nPhase 31 Specific Findings Discovered:")
        found_any = False
        for f in result.get("findings", []):
            if f.get("name") in phase31_names:
                found_any = True
                print(f"\\n- {f.get('name')} ({f.get('severity')})")
                print(f"  {f.get('description')}")
                if "evidence" in f and "raw" in f["evidence"]:
                    print(f"  Evidence:\\n{f['evidence']['raw']}")
                    
        if not found_any:
            print("No Phase 31 specific findings were generated for this target.")
            
    except Exception as e:
        print(f"Error during scan: {e}")

if __name__ == "__main__":
    main()
