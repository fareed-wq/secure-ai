import sys
import time
import requests

# Import registered modules from your backend engine
try:
    from api.index import REGISTERED_MODULES
except ImportError:
    try:
        from index import REGISTERED_MODULES
    except ImportError:
        print("❌ Could not import REGISTERED_MODULES from api/index.py.")
        print("   Make sure you run this script from your project root directory.")
        sys.exit(1)

# Terminal ANSI Color Formatting
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# Benchmark Target Definitions
BENCHMARK_TARGETS = [
    # --- Existing 6 Benchmark Targets ---
    {
        "name": "TLS Expiration Test (badssl.com)",
        "url": "https://expired.badssl.com",
        "check_type": "finding_status",
        "expected_statuses": ["high", "medium", "critical"],
        "finding_keyword": "ssl",
        "description": "Verifies that expired SSL certificates trigger security alerts."
    },
    {
        "name": "Missing HSTS & Redirection Test (neverssl.com)",
        "url": "http://neverssl.com",
        "check_type": "finding_status",
        "expected_statuses": ["medium", "high"],
        "finding_keyword": "hsts",
        "description": "Verifies that unencrypted sites with missing HSTS/HTTPS are flagged."
    },
    {
        "name": "SPA Soft-404 False-Positive Test (nextjs.org)",
        "url": "https://nextjs.org",
        "check_type": "anti_false_positive",
        "forbidden_findings": ["Exposed Admin Portal", "Exposed .env Configuration File"],
        "description": "Verifies that Next.js catch-all routes do NOT trigger false positives."
    },
    {
        "name": "Subdomain Takeover Apex Domain Test (github.com)",
        "url": "https://github.com",
        "check_type": "finding_status",
        "expected_statuses": ["passed"],
        "finding_keyword": "subdomain takeover",
        "description": "Verifies clean PASSED status for apex domains with direct IP records."
    },
    {
        "name": "Missing DNS CAA Test (neverssl.com)",
        "url": "http://neverssl.com",
        "check_type": "finding_status",
        "expected_statuses": ["low", "info", "informational", "passed"],
        "finding_keyword": "caa",
        "description": "Verifies DNS CAA module handles domains with or without CAA."
    },
    {
        "name": "CORS & Security Headers Audit (api.github.com)",
        "url": "https://api.github.com",
        "check_type": "finding_status",
        "expected_statuses": ["info", "informational", "low", "medium", "passed"],
        "finding_keyword": "cors",
        "description": "Verifies CORS header evaluation on public REST APIs."
    },

    # --- 4 New Benchmark Targets ---
    {
        "name": "Self-Signed Certificate Test (badssl.com)",
        "url": "https://self-signed.badssl.com",
        "check_type": "finding_status",
        "expected_statuses": ["high", "critical", "medium"],
        "finding_keyword": "ssl",
        "description": "Verifies detection of untrusted or self-signed SSL/TLS certificates."
    },
    {
        "name": "Enterprise Email Security (google.com)",
        "url": "https://google.com",
        "check_type": "finding_status",
        "expected_statuses": ["passed", "info", "informational"],
        "finding_keyword": "dmarc",
        "description": "Verifies strict SPF and DMARC enforcement on enterprise domains."
    },
    {
        "name": "Security Policy Disclosure (securitytxt.org)",
        "url": "https://securitytxt.org",
        "check_type": "finding_status",
        "expected_statuses": ["passed", "info", "informational"],
        "finding_keyword": "security.txt",
        "description": "Verifies detection of standard .well-known/security.txt files."
    },
    {
        "name": "Legacy Weak Cipher Test (badssl.com)",
        "url": "https://rc4.badssl.com",
        "check_type": "finding_status",
        "expected_statuses": ["medium", "high"],
        "finding_keyword": "cipher",
        "description": "Verifies detection of deprecated or weak SSL/TLS ciphers."
    }
]

def run_benchmark_suite():
    print(f"\n{CYAN}=============================================================={RESET}")
    print(f"{CYAN} 🧪 URLScanOnline - Automated Accuracy & Anti-Bloat Test Suite {RESET}")
    print(f"{CYAN}=============================================================={RESET}\n")

    session = requests.Session()
    total_tests = len(BENCHMARK_TARGETS)
    passed_tests = 0

    for idx, test in enumerate(BENCHMARK_TARGETS, 1):
        print(f"[{idx}/{total_tests}] Testing: {CYAN}{test['name']}{RESET}")
        print(f"    Target: {test['url']}")
        print(f"    Scope:  {test['description']}")

        url = test['url']
        hostname = url.split("://")[-1].split("/")[0]

        # Run all registered backend modules against target
        findings = []
        start_time = time.time()
        
        for module in REGISTERED_MODULES:
            try:
                mod_findings = module.run(url, hostname, session)
                if mod_findings:
                    findings.extend(mod_findings)
            except Exception as e:
                print(f"    {YELLOW}⚠️ Module '{module.module_name}' threw non-fatal exception: {e}{RESET}")

        duration = round((time.time() - start_time) * 1000, 2)
        print(f"    Execution Time: {duration} ms | Total Findings Returned: {len(findings)}")

        test_passed = True
        failure_reasons = []

        # Logic Validation Mode 1: Expecting Specific Finding Severity
        if test["check_type"] == "finding_status":
            keyword = test["finding_keyword"].lower()
            matching_findings = [
                f for f in findings 
                if keyword in f.get('name', '').lower() or keyword in f.get('category', '').lower()
            ]
            
            # Note: the script uses 'status' instead of 'severity'. Our api/index.py returns 'severity'.
            # I will modify the script slightly to check both 'severity' and 'status' just in case.
            matched_status = any(
                str(f.get('severity', f.get('status', ''))).lower() in [s.lower() for s in test['expected_statuses']]
                for f in matching_findings
            )
            
            if not matched_status:
                test_passed = False
                failure_reasons.append(
                    f"Expected keyword '{keyword}' with status in {test['expected_statuses']}, but got: "
                    f"{[f.get('severity', f.get('status')) for f in matching_findings]}"
                )

        # Logic Validation Mode 2: Anti-False-Positive Inspection
        elif test["check_type"] == "anti_false_positive":
            for forbidden in test["forbidden_findings"]:
                fp_findings = [
                    f for f in findings 
                    if forbidden.lower() in f.get('name', '').lower() 
                    and f.get('severity', f.get('status')) not in ['Passed', 'Info']
                ]
                if fp_findings:
                    test_passed = False
                    failure_reasons.append(
                        f"FALSE POSITIVE DETECTED! Module returned '{forbidden}' as a vulnerability."
                    )

        # Print Test Results
        if test_passed:
            print(f"    Status: {GREEN}✅ PASSED{RESET}\n")
            passed_tests += 1
        else:
            print(f"    Status: {RED}❌ FAILED{RESET}")
            for reason in failure_reasons:
                print(f"      - {reason}")
            print()

    print(f"{CYAN}=============================================================={RESET}")
    print(f"📊 SUMMARY: {passed_tests}/{total_tests} Benchmark Tests Passed.")
    
    if passed_tests == total_tests:
        print(f"{GREEN}🎉 All engine accuracy & anti-false-positive guardrails verified!{RESET}\n")
    else:
        print(f"{RED}⚠️ Some accuracy checks failed. Review logic in api/index.py.{RESET}\n")

if __name__ == "__main__":
    run_benchmark_suite()
