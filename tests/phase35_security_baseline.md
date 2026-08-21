# Phase 35: Security Baseline Audit

## 1. Current SSRF Protections
- `is_public_hostname` currently uses `socket.getaddrinfo` to resolve the host and checks against `ipaddress.is_private`, `is_loopback`, `is_link_local`, `is_reserved`, `is_multicast`.
- **Finding:** `ipaddress.ip_address.is_private` does not cover CGNAT (`100.64.0.0/10`).
- The protection is correctly positioned but needs expanded explicit checks for `0.0.0.0/8`, `100.64.0.0/10`, IPv4-mapped IPv6, and `::1`.

## 2. URL Validation Flow
- `api.scanner.validation.canonicalize_url` regexes the input to find the first `http/https` URL.
- **Finding:** There is no strict length limit applied to the raw input, which could lead to ReDoS or memory issues if an attacker submits an extremely long string.

## 3. DNS Validation Flow
- Handled at the top level by `is_public_hostname`, but more importantly, `SafeHTTPAdapter` and `SafePoolManager` enforce that urllib3 connects using `safe_create_connection`.
- `safe_create_connection` re-resolves the IP, re-validates every IP, and connects directly to the validated `sockaddr`. This natively prevents DNS Rebinding / TOCTOU attacks.

## 4. Redirect Handling
- `safe_request` disables default `requests` redirects (`allow_redirects=False`) and manually follows `Location` headers up to `Config.MAX_REDIRECTS`.
- The new URL is parsed and passed to `is_public_hostname`.
- **Finding:** Redirects are currently subjected to the public hostname check. However, we should explicitly check the scheme of the redirect `Location` to ensure it is only `http` or `https` (and prevent `file://`, `gopher://`, etc.).

## 5. HTTP Request Limits
- Total scan runtime is bounded to 25 seconds.
- Requests per module are not strictly limited by count, but time limits prevent infinite requests.
- The `Config.MAX_REDIRECTS` is set to 5.

## 6. Response-size limits (Critical Finding)
- `JavaScriptSecurityModule` limits reading to `2,000,000` bytes (2MB) by using `stream=True` and `iter_content`.
- **Finding:** `safe_request` does *not* enforce a global response limit for non-streamed requests. Because `stream=False` is the default in `requests`, a malicious server returning a 10GB `robots.txt` or HTML page will cause the `requests` library to buffer 10GB into memory, leading to Resource Exhaustion / OOM.
- **Finding:** Decompression (gzip/br) is transparently handled by `requests`, making the scanner vulnerable to decompression bombs if `stream=False`.

## 7. Timeout Handling
- Handled via `Config.REQUEST_TIMEOUT = (1.5, 2.5)` and enforced on all `safe_request` calls.
- Overall module execution is limited by `SCAN_BUDGET_SECONDS` (25s) with manual thread cancellation.

## 8. Concurrency Limits
- `ThreadPoolExecutor` in `orchestrator.py` is bounded by `Config.THREAD_POOL_SIZE` (15).
- Some modules spawn small thread pools (e.g., `max_workers=2` in `discovery.py`).
- Thread pools are safely terminated using `pool.shutdown(wait=False, cancel_futures=True)`.

## 9. Cache Isolation
- Caches (`_request_cache` and `_dns_cache`) are bound to the `requests.Session` instance.
- A new `Session` is instantiated per target in `orchestrator.py`.
- **Finding:** Targets are fully isolated; one target cannot poison the cache of another. The cache key includes `method`, `url`, and `headers_tuple`, preventing collisions.

## 10. Evidence/Logging Protections
- `JavaScriptSecurityModule` masks secrets using a custom mask method.
- **Finding:** We must ensure exception strings caught in `orchestrator.py` do not leak sensitive internal paths if an internal error occurs.

## 11. Exception Handling
- `safe_request` catches generic `Exception` and returns it inside the cache or as `None`.
- Most modules safely handle `requests.exceptions.RequestException`.

## 12. Input Validation
- Covered under URL validation. Needs URL length enforcement.

## 13. Existing Abuse Protections
- In-memory and Upstash Redis rate limiting exists in `core.py` (`check_rate_limit`).

## 14. Genuine Weaknesses Discovered (Action Items for Phase 35)
1. **Unbounded Response Size:** `safe_request` must enforce a global maximum response size (e.g., 5MB) for all requests to prevent memory exhaustion and decompression bombs.
2. **SSRF Gaps:** Explicitly block `100.64.0.0/10` (CGNAT) and ensure `0.0.0.0/8` is blocked.
3. **Redirect Schemes:** Validate redirect schemes in `safe_request` to enforce `http` and `https`.
4. **Input Lengths:** Enforce max URL length in `canonicalize_url`.
5. **Exception Masking:** Ensure `orchestrator.py` truncates/sanitizes exception strings.
