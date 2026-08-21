import asyncio
from api.scanner.orchestrator import scan_url

async def main():
    print("Testing failed connection (should not have score):")
    res1 = await asyncio.to_thread(scan_url, "http://127.0.0.1:9999", False)
    print("Result 1 status:", res1.get("status"))
    print("Result 1 score present:", "score" in res1)
    print("Result 1 error:", res1.get("error"))

    print("\nTesting successful target (should have COMPLETED and score):")
    res2 = await asyncio.to_thread(scan_url, "https://google.com", False)
    print("Result 2 status:", res2.get("status"))
    print("Result 2 score:", res2.get("score"))
    print("Result 2 summary:", res2.get("executive_summary"))

if __name__ == "__main__":
    asyncio.run(main())
