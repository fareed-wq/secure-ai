# Phase 33 - Coverage & Accuracy Matrix

This matrix evaluates the Secure-AI passive vulnerability scanner's actual implementation against the security capabilities established in prior phases.

## API / Web Discovery
| Capability | Status | Module | Notes |
|---|---|---|---|
| OpenAPI | PASS | `OpenApiModule` | Accurately identifies `openapi.json` and `swagger.json`. |
| Swagger | PASS | `OpenApiModule` | Covered alongside OpenAPI. |
| Swagger UI | PASS | `OpenApiModule` | Identified via evidence extraction. |
| GraphQL IDE | PASS | `GraphqlIdeModule` | Detects GraphiQL, GraphQL Playground, Altair. |
| GraphQL references | PASS | `ApiWebSecurityModule` | Detects `/graphql` endpoint references in JavaScript. |
| Spring Boot Actuator | PASS | `ActuatorModule` | Accurately identifies actuator endpoints and determines if sensitive (e.g. `/env`). |
| XML-RPC | PASS | `XmlRpcModule` | Accurately identifies `xmlrpc.php`. |
| security.txt | PASS | `SecurityTxtModule` | Checks `/.well-known/security.txt` and `/security.txt`. |
| robots.txt | PASS | `RobotsTxtModule` | Accurately identifies `robots.txt` and extracts sensitive paths. |
| sitemap | PASS | `SitemapModule` | Checks for `sitemap.xml`. |
| exposed sensitive files | PASS | `ExposedFilesModule` | General detection. |
| `.env` | PASS | `ExposedFilesModule` | Explicit check for `/.env`. |
| `.git/HEAD` | PASS | `ExposedFilesModule` | Explicit check for `/.git/HEAD`. |
| phpinfo | PASS | `ExposedFilesModule` | Explicit check for `/phpinfo.php`. |
| API documentation | PASS | `ApiWebSecurityModule` | Checks for `/api-docs` etc. |
| privileged API routes | PASS | `OpenApiModule`, `JavaScriptSecurityModule` | Extracted and cross-correlated. |

## JavaScript Security
| Capability | Status | Module | Notes |
|---|---|---|---|
| JS bundle discovery | PASS | `JavaScriptSecurityModule` | Accurately parses HTML for `<script>` tags. |
| Same-origin enforcement | PASS | `JavaScriptSecurityModule` | Enforces scanning only for same-origin or relative URLs. |
| Bundle limits | PASS | `JavaScriptSecurityModule` | Enforces 10 bundle limit. |
| Source-map detection | PASS | `JavaScriptSecurityModule` | Accurately identifies `.map` URLs. |
| Source-map validation | PASS | `JavaScriptSecurityModule` | Parses JSON and checks for `version`, `sources`. |
| `sourcesContent` | PASS | `JavaScriptSecurityModule` | Checks for source content leakage in maps. |
| Secret detection | PASS | `JavaScriptSecurityModule` | Regex checks for various secrets. |
| Secret masking | PASS | `ScannerModule` | Centralized masking of secrets via `make_finding`. |
| Public-key detection | PASS | `JavaScriptSecurityModule` | Avoids flagging non-secret public keys. |
| Frontend config exposure | PASS | `JavaScriptSecurityModule` | Identifies configuration/debug blocks. |
| Debug artifacts | PASS | `JavaScriptSecurityModule` | Identifies `console.log` use. |
| Internal infra references | PASS | `JavaScriptSecurityModule` | Extracted. |
| API endpoint discovery | PASS | `JavaScriptSecurityModule` | Regex for paths like `/api/v1/`. |
| API version discovery | PASS | `ApiWebSecurityModule` | Detects `/v1/`, `/v2/` in API URLs. |
| Framework fingerprinting | PASS | `JavaScriptSecurityModule` | Detects React, Angular, Vue, jQuery, etc. |
| Library version detection | PASS | `JavaScriptSecurityModule` | Extracts versions. |
| Sequential identifiers | PASS | `JavaScriptSecurityModule` | Extracts potential IDOR paths (e.g. `/api/users/{id}`). |
| Privileged auth logic | PASS | `JavaScriptSecurityModule` | Identifies `isAdmin`, `hasRole`, etc. |
| Role/permission disclosure| PASS | `JavaScriptSecurityModule` | Identifies `ROLE_ADMIN`, etc. |
| Sensitive API models | PASS | `JavaScriptSecurityModule` | Extracts potentially sensitive schema references. |

## HTTP / Web Security
| Capability | Status | Module | Notes |
|---|---|---|---|
| Security headers | PASS | `SecurityHeadersModule` | Checks common headers. |
| CSP | PASS | `SecurityHeadersModule` | Validates CSP presence. |
| CSP weak directives | PASS | `SecurityHeadersModule` | Parses and identifies `unsafe-inline`, wildcard, etc. |
| HSTS | PASS | `SecurityHeadersModule` | Validates HSTS presence and attributes. |
| Referrer-Policy | PASS | `SecurityHeadersModule` | Validates presence and values. |
| COOP | PASS | `AdvancedSecurityHeadersModule` | Validates presence. |
| COEP | PASS | `AdvancedSecurityHeadersModule` | Validates presence. |
| CORP | PASS | `AdvancedSecurityHeadersModule` | Validates presence. |
| API context awareness | PASS | `SecurityHeadersModule` | Suppresses UI-only findings on `application/json` responses. |
| CORS | PASS | `CORSModule` | Sends custom origin, checks for reflection/wildcard. |
| Redirect chains | PASS | `ApiWebSecurityModule` | Identifies chains > 5. |
| TRACE advertisement | PASS | `ApiWebSecurityModule` | Checks `Allow` header for TRACE. |
| API content-type mismatch | PASS | `ApiWebSecurityModule` | Validates JSON bodies have correct `Content-Type`. |
| API cache posture | PASS | `ApiWebSecurityModule` | Warns if API endpoints have missing or public cache controls. |
| API error disclosure | PASS | `ApiWebSecurityModule`, `VerboseStackTraceModule` | Detects stack traces and sensitive error formats. |
| OIDC discovery | PASS | `ApiWebSecurityModule` | Checks `/.well-known/openid-configuration`. |
| WebSocket discovery | PASS | `ApiWebSecurityModule` | Detects `ws://` / `wss://` patterns. |
| Authentication portal | PASS | `AuthenticationSessionSecurityModule` | Detects login pages and form structures. |
| GraphQL/API docs | PASS | `ApiWebSecurityModule` | References. |
| Server version disclosure | PASS | `TechFingerprintModule` | Checks `Server` and `X-Powered-By` for versions. |

## Authentication / Session / Cookies
| Capability | Status | Module | Notes |
|---|---|---|---|
| Authentication form | PASS | `AuthenticationSessionSecurityModule` | Accurate detection of login/password forms. |
| Password fields | PASS | `AuthenticationSessionSecurityModule` | Checks for `<input type="password">`. |
| Form actions | PASS | `AuthenticationSessionSecurityModule` | Extracts and validates the `action` attribute. |
| Cross-origin auth forms | PASS | `AuthenticationSessionSecurityModule` | Detects if form posts to external domain. |
| CSRF posture | PASS | `AuthenticationSessionSecurityModule` | Checks for anti-CSRF tokens in forms. |
| WWW-Authenticate | PASS | `AuthenticationSessionSecurityModule` | Checks HTTP Basic/Digest headers. |
| Basic auth over HTTP | PASS | `AuthenticationSessionSecurityModule` | Detects if Basic auth is advertised on non-HTTPS. |
| OAuth/OIDC/SAML | PASS | `AuthenticationSessionSecurityModule` | Tech fingerprinting. |
| Firebase/Auth0 | PASS | `AuthenticationSessionSecurityModule` | Tech fingerprinting. |
| Password reset | PASS | `AuthenticationSessionSecurityModule` | Detects recovery interfaces. |
| Session cookie ID | PASS | `AdvancedCookieModule` | Accurately differentiates session vs non-session via keywords. |
| Secure | PASS | `AdvancedCookieModule` | Validates flag. |
| HttpOnly | PASS | `AdvancedCookieModule` | Validates flag. |
| SameSite | PASS | `AdvancedCookieModule` | Validates flag and values. |
| Cookie Domain | PASS | `AdvancedCookieModule` | Warns on broad domain scope. |
| `__Host-` | PASS | `AdvancedCookieModule` | Validates prefix rules. |
| `__Secure-` | PASS | `AdvancedCookieModule` | Validates prefix rules. |
| Cookie value masking | PASS | `AdvancedCookieModule` | Redacts values to `[REDACTED]`. |
| Sensitive-page cache | PASS | `AuthenticationSessionSecurityModule` | Checks caching headers on auth pages. |

## Authorization / Access Control
| Capability | Status | Module | Notes |
|---|---|---|---|
| Admin surface discovery | PASS | `ExposedFilesModule` | Checks common admin paths. |
| Privileged paths | PASS | `RobotsTxtModule` | Extracts admin paths from robots.txt. |
| Role model disclosure | PASS | `JavaScriptSecurityModule` | Detects hardcoded roles. |
| Client-side auth logic | PASS | `JavaScriptSecurityModule` | Detects client-side authorization enforcement code. |
| Privileged API references | PASS | `JavaScriptSecurityModule` | Identifies sensitive API paths. |
| OpenAPI auth schemes | PASS | `OpenApiModule` | Parses `securitySchemes`. |
| OpenAPI privileged ops | PASS | `OpenApiModule` | Finds admin endpoints in swagger spec. |
| Robots privileged paths | PASS | `RobotsTxtModule` | Detects admin paths in robots.txt. |
| Cross-layer correlation | PASS | `orchestrator` | Correlates API, HTML, JS, Robots privileged data. |
| Missing/weak auth | PASS | `OpenApiModule` | Warns if privileged routes are listed without security. |

## DNS / Infrastructure
| Capability | Status | Module | Notes |
|---|---|---|---|
| CAA | PASS | `DNSCAAModule` | Checks DNS records via DoH. |
| DNSSEC | PASS | `DNSCAAModule` | Checks DS records. |
| Wildcard DNS | PASS | `DNSCAAModule` | Checks nonexistent subdomains. |
| SPF | PASS | `DNSEmailSecurityModule` | Validates SPF records. |
| Multiple SPF | PASS | `DNSEmailSecurityModule` | Flags if > 1 SPF record exists. |
| Permissive SPF | PASS | `DNSEmailSecurityModule` | Flags `+all`. |
| DMARC | PASS | `DNSEmailSecurityModule` | Validates DMARC. |
| DMARC `p=none` | PASS | `DNSEmailSecurityModule` | Flags monitoring-only mode. |
| DMARC quarantine/reject| PASS | `DNSEmailSecurityModule` | Validates strong policy. |
| DKIM | PASS | `DNSEmailSecurityModule` | Checks common selectors. |
| MTA-STS | PASS | `DNSEmailSecurityModule` | Validates MTA-STS. |
| Certificate SANs | PASS | `InfrastructureIntelligenceModule` | Extracts Subject Alternative Names. |
| Cloud provider | PASS | `InfrastructureIntelligenceModule` | Fingerprints CNAMEs for AWS/GCP/Azure. |
| DNS provider | PASS | `InfrastructureIntelligenceModule` | Fingerprints NS records. |
| Mail provider | PASS | `InfrastructureIntelligenceModule` | Fingerprints MX records. |
| Dangling cloud resource| PASS | `SubdomainTakeoverModule`, `InfrastructureIntelligenceModule` | Checks for vulnerable CNAMEs. |
| Hostname classification | PASS | `orchestrator` | Classifies discovered hostnames (API, Stage, Mail, etc). |
| Cross-module correlation| PASS | `orchestrator` | Aggregates infrastructure intelligence. |

## General Security Architecture
| Capability | Status | Module | Notes |
|---|---|---|---|
| Finding schema | PASS | `ScannerModule` | Centralized `make_finding`. |
| Deterministic ID | PASS | `scan_url` / UI | Schema provides standard name/category matching. |
| Evidence truncation | PASS | `ScannerModule` | Enforced at 180 chars (or 1000 for specific findings). |
| Secret masking | PASS | `ScannerModule` | Occurs *before* truncation. |
| Severity consistency | PASS | `calculate_score` | Standard severity levels handled. |
| Confidence consistency | PASS | `ScannerModule` | Standard confidence levels. |
| CVSS assignment | PASS | `ScannerModule` | Maps Severity to standard CVSS v3.1 vectors. |
| Duplicate suppression | PASS | `calculate_score` | Identifies and deduplicates based on signature. |
| Score stability | PASS | `calculate_score` | Handles informational=0 penalty. |
| Module timeout | PASS | `orchestrator` | `SCAN_BUDGET_SECONDS=25` enforced. |
| Exception isolation | PASS | `orchestrator` | Modules run in `ThreadPoolExecutor` and trap exceptions. |
| Scan-budget compliance | PASS | `orchestrator` | Enforced via `as_completed` timeout. |
| SSRF protections | PASS | `transport` | `is_public_hostname` prevents private IP scanning. |
