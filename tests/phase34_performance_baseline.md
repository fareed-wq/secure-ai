# Phase 34 - Performance Baseline

## 1. Current Architecture
The scanner uses a `ThreadPoolExecutor` (typically 10-25 workers based on `Config.THREAD_POOL_SIZE`) managed by `api/scanner/orchestrator.py`.
- **Global Budget**: 25 seconds.
- **Module Execution**: 30 modules run concurrently, each with an 8s default timeout.
- **Transport**: `api/scanner/transport.py` providing `safe_request()` which implements redirects, strict cookie dropping, and SSRF socket wrappers.

## 2. Approximate Request Count
Currently, modules operate in isolation. This causes significant duplication:
- Multiple modules request the root URL `/` (`HTTPSRedirectModule`, `ExposedFilesModule`, `MixedContentModule`, `Headers` modules, `Content` modules).
- Multiple modules request `/robots.txt` and `/sitemap.xml`.
- JavaScript bundles are downloaded and parsed by `JavaScriptSecurityModule`, but source maps or bundles might be large.
- Total requests per scan routinely exceed 50+ when considering timeouts, subdomains, and redirects.

## 3. Known Bottlenecks
- **Duplicate Requests**: `safe_request()` does not cache identical requests across modules in the same scan session.
- **DNS/TLS Blocking**: `is_public_hostname` performs synchronous `socket.getaddrinfo` on every request and redirect hop. This adds significant latency.
- **Regex Compilation**: Many modules (e.g., `api_web_security`, `auth_session_security`, `discovery`) compile regex strings locally inside functions rather than at the module level, meaning they recompile per scan or loop.
- **Unbounded Processing**: While `JavaScriptSecurityModule` limits reads to 2MB, `api_web_security.py` or others might parse large JSON bodies multiple times.

## 4. Timeout Risks
- If a target is a tarpit, `safe_request` timeouts are correctly bounded to `(1.5, 2.5)`. However, doing 5 identical requests means 5 * 2.5 = 12.5s of wasted thread time. Caching failures/timeouts for the same URL will save massive amounts of time.
- `ThreadPoolExecutor` does not eagerly cancel running requests when the global 25s timeout hits, which can leave background threads running.

## 5. Recommended Optimizations
- **Session-scoped Request Cache**: Add a `request_cache` dict to the `requests.Session` in `get_http_session()`. Have `safe_request` check this cache (keyed by method + url) and return the cached `requests.Response` immediately. This prevents duplicate downloads of `/` and large files.
- **Regex Hoisting**: Move `re.compile()` calls to the class/module level in `api_web_security.py`, `auth_session_security.py`, and `discovery.py`.
- **DNS Resolution Cache**: Cache `is_public_hostname` results for the duration of the scan to prevent repetitive `getaddrinfo` calls for the same host.
- **Fast-fail Caching**: Cache timeouts/connection errors so multiple modules don't wait on the same dead URL.

## 6. Constraints - What NOT to optimize
- Do not increase the 25-second global budget.
- Do not increase the 10 JS bundle / 2MB limits.
- Do not bypass SSRF socket protections (`safe_create_connection`).
- Do not persist cache across different scans (cache must be tied to the `session` object).
