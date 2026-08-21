# Security Philosophy & Authorized Use

## Passive Security Posture
Secure-AI operates exclusively on a **passive and non-intrusive** security model. The scanner does not actively exploit vulnerabilities, bypass authentication, or attempt to modify data on target systems.

The core philosophy is to behave like a standard, well-behaved web client (similar to a browser) while deeply analyzing the metadata, HTTP headers, DNS records, and publicly accessible surface area of a web property.

## What The Scanner Does
- **Metadata Analysis:** Reviews publicly broadcasted headers and HTML source.
- **DNS Probing:** Queries public nameservers for SPF, DMARC, CAA, and subdomains.
- **TLS Handshakes:** Initiates SSL/TLS handshakes to determine certificate validity and supported ciphers, without sending HTTP payloads over weak ciphers.
- **Known-Path Discovery:** Issues standard GET requests to well-known administrative or metadata paths (e.g., `robots.txt`, `.env`, `.git/HEAD`) and checks for 200 OK responses indicating accidental exposure.

## What The Scanner Explicitly Does NOT Do
- **No Payload Injection:** Does not send SQLi, XSS, or OS Command Injection payloads.
- **No Brute-Forcing:** Does not attempt to guess passwords or brute-force administrative directories.
- **No Denial of Service:** Does not overwhelm the target with requests. Built-in rate limiting ensures requests are throttled and lightweight.
- **No Authentication Bypassing:** Does not test for IDOR or Broken Access Control vulnerabilities requiring session hijacking.

## Authorized Use & Responsibility
By utilizing Secure-AI, users agree that they have the explicit authorization to scan the target web properties. 
- **SSRF Protections:** The scanner backend enforces strict Server-Side Request Forgery (SSRF) protections. It will actively reject requests to `localhost`, `127.0.0.1`, AWS metadata endpoints (`169.254.169.254`), and private RFC 1918 IP addresses.
- **Responsibility:** All findings are provided for informational and defensive purposes. Users are responsible for verifying findings and responsibly disclosing any discovered vulnerabilities to the property owners.

## Data Retention & Privacy
- **Scanned Artifacts:** Scan reports are generated in real-time. If authenticated, results are securely stored in the Supabase backend strictly for the user's historical reference.
- **No Sensitive Evidence Extraction:** When checking for exposed sensitive files (like `.env`), the scanner validates the HTTP status and content type but truncates the payload to prevent logging or storing the victim's raw credentials.
