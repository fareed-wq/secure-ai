# Security Philosophy & Authorized Use

## Passive-First Security Posture
URLScannerOnline operates on a **passive-first, low-impact** security model. The scanner does not actively exploit vulnerabilities, bypass authentication, or attempt to modify data on target systems.

**Basic Scan:** Operates exclusively as a passive client, analyzing metadata, HTTP headers, DNS records, and publicly accessible surface area.
**Advanced Scan:** Operates as an authorized passive-first/low-impact scanner. It performs bounded additional HTTP, DNS, and limited TCP checks but remains strictly non-exploitative.

## What The Scanner Does
- **Metadata Analysis:** Reviews publicly broadcasted headers and HTML source.
- **DNS Probing:** Queries public nameservers for SPF, DMARC, CAA, and subdomains.
- **TLS Handshakes:** Initiates SSL/TLS handshakes to determine certificate validity and supported ciphers, without sending HTTP payloads over weak ciphers.
- **Known-Path Discovery:** Issues standard GET requests to well-known administrative or metadata paths and checks for 200 OK responses indicating accidental exposure.

## What The Scanner Explicitly Does NOT Do
- **No Payload Injection:** Does not send SQLi, XSS, or OS Command Injection payloads.
- **No Brute-Forcing:** Does not attempt to guess passwords or brute-force administrative directories.
- **No Denial of Service:** Does not overwhelm the target with requests. Built-in rate limiting ensures requests are throttled and lightweight.
- **No Authentication Bypassing:** Does not test for IDOR or Broken Access Control vulnerabilities requiring session hijacking.

## Authorized Use & Responsibility
By utilizing URLScannerOnline, users agree that they have explicit authorization to scan the target web properties. Ad-hoc Advanced scans require explicit authorization acknowledgement, while scheduled Advanced scans require a recurring authorization acknowledgement.
- **SSRF Protections:** The scanner backend enforces strict Server-Side Request Forgery (SSRF) protections. It actively rejects requests to localhost, 127.0.0.1, AWS metadata endpoints (169.254.169.254), and private RFC 1918 IP addresses.
- **Responsibility:** All findings are provided for informational and defensive purposes. Users are responsible for verifying findings and responsibly disclosing any discovered vulnerabilities.

## Application Authorization
- **Server-Side Authority:** Server-side authorization remains authoritative at all times. UI state is never trusted for critical actions.
- **Supabase Auth/RLS:** Identity and row-level access control are enforced securely via Supabase.
- **Schedule Scans Access:** Currently an admin-only capability. (Future paid capabilities may allow broader access, but this is NOT LIVE).

## Scheduled Scan Security
- **Signature Verification:** The schedule worker endpoint verifies the QStash signature.
- **Opaque Payloads:** The QStash body contains only the schedule_id.
- **Authoritative State:** The authoritative schedule, user, target, and mode are loaded securely server-side.
- **Acknowledgement:** Advanced scheduled scans require a recurring authorization acknowledgement.
- **Resilience:** A temporary entitlement lookup failure (e.g. backend error) does not equal ineligibility and will not permanently disable the schedule.

## Scheduled Email Security
- **Dedicated Worker:** Handled by a separate authenticated and signature-verified worker endpoint.
- **Opaque Payloads:** The QStash body contains only the
un_id.
- **Verified Recipient:** Emails are strictly sent to the user's current verified account email. There are no arbitrary recipients, CCs, or BCCs.
- **Safe Payload:** The email body contains a safe executive summary. Deep technical evidence is isolated within the attached PDF.
- **Idempotency:** Email delivery utilizes deterministic idempotency (e.g., scheduled-report-<run_id>).
- **No Permanent Artifacts:** There is no permanent storage of the generated PDF.

## Logging / Privacy
- **Scanned Artifacts:** If authenticated, scan results are securely stored in the Supabase backend strictly for the user's historical reference.
- **Evidence Truncation:** When checking for exposed sensitive files, the scanner truncates the payload to prevent logging or storing the victim's raw credentials.
- **Explicit Prohibitions:** The application explicitly prohibits the logging of:
  - Recipient emails
  - Target findings/evidence or raw report data
  - Tokens and authorization headers
  - Provider raw responses
  - Secrets
- Opaque internal UUIDs may be used for correlation when appropriate.
