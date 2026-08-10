import time
from api.scanner.orchestrator import scan_url

if __name__ == "__main__":
    start = time.time()
    scan_url("https://example.com")
    end = time.time()
    print(f"Total orchestrator runtime: {end - start:.2f}s")
