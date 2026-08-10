# Phase 38 — CVSS & Finding Evidence Accuracy Audit

## 1. Current CVSS Generation Mechanism
The CVSS v3.1 vectors are generated natively during the finalization stage of `ScannerBase.make_finding()` located in `api/scanner/base.py`. They are attached directly to the finding object under the `cvss` key before the report is consolidated. 

## 2. Default vs. Calculated CVSS Values
The CVSS values are **severity-based defaults** and are **hardcoded** rather than dynamically calculated per-vulnerability basis. 
The system does not dynamically adjust vectors (e.g. `AV:L` vs `AV:N`) based on contextual evidence; it strictly assigns a blanket vector linked exclusively to the categorical severity rating (Low, Medium, High, Critical) passed by the scanner module.

## 3. CVSS Mapping Table by Severity

| Severity | Default Hardcoded CVSS v3.1 Vector | Note |
|---|---|---|
| **Critical** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | Network attack, no privileges, scope changed. Maximum impact. |
| **High** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | Network attack, no privileges, high confidentiality impact only. |
| **Medium** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` | Network attack, requires user interaction (UI:R), low impact. |
| **Low** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | Network attack, high complexity, low confidentiality impact. |
| **Informational** | *None* | Excluded from CVSS metrics. |
| **Passed** | *None* | Excluded from CVSS metrics. |

## 4. UI Representation
The UI presentation in `TechnicalReport.jsx` faithfully maps to the underlying implementation. The finding displays:
`CVSS v3.1 (Severity Default): [Vector String]`
This label is **100% accurate** because it transparently discloses to the user that the vector is a severity-based default rather than a dynamically scored metric. It does not mislead the user with an arbitrary numeric score.

## 5. Evidence-to-Finding Accuracy Audit

### A. Legacy Weak TLS Ciphers Supported
**Finding Evidence:** `Server negotiated: TLS_AES_128_GCM_SHA256 (TLSv1.3)`
**Accuracy:** **FALSE POSITIVE / MISLEADING**
- **Investigation:** In `api/scanner/modules/network_checks.py`, the scanner creates a TLS context, sets `weak_ctx.verify_mode = ssl.CERT_NONE`, and applies `weak_ctx.set_ciphers("3DES:RC4:DES:MD5:EXPORT")`. It then attempts a handshake. 
- **The Defect:** Python's `ssl.create_default_context()` implicitly supports TLS 1.3 by default. OpenSSL's `set_ciphers()` string configuration *does not apply to TLS 1.3 ciphers* (they are controlled independently via `set_ciphersuites()`). Because the scanner fails to explicitly restrict the maximum TLS version to TLS 1.2 on `weak_ctx`, any modern server supporting TLS 1.3 simply ignores the legacy cipher list, negotiates a perfectly secure TLS 1.3 handshake (e.g., `TLS_AES_128_GCM_SHA256`), and the scanner erroneously marks `weak_supported = True`.
- **Verdict:** The finding triggers heavily on secure modern architectures as a false positive.

### B. Internal Infrastructure References Disclosed in Client-Side Code
**Finding Evidence:** `http://localhost:5000`, `http://192.168.1.10:8080`
**Accuracy:** **ACCURATE**
- **Investigation:** The scanner leverages carefully bounded regex patterns `(?::\d+)?` to extract explicit internal IP addresses, local network spaces, and localhost strings from compiled JavaScript blocks. 
- **Verdict:** The evidence genuinely proves the finding by locating functional internal endpoints, properly isolating them from generic string usage.

### C. Authentication Response May Be Publicly Cacheable
**Finding Evidence:** `Cache-Control: public, max-age=0, must-revalidate` (or `no-store`)
**Accuracy:** **ACCURATE**
- **Investigation:** Following the recent patch, the scanner natively parses the cache directives. It correctly filters out `no-store` and `private` responses, drops the severity of `max-age=0, must-revalidate` to **Low**, and retains `public` with positive cache duration as **Medium**.
- **Verdict:** The displayed header evidence directly correlates with the mapped severity scale.

## 6. Recommended Fixes (Do NOT Implement Yet)
The only structural defect identified during the audit is the legacy cipher probe.

To resolve the TLS cipher false positive, the context must strictly prevent TLS 1.3 negotiation so the server is forced to either accept a legacy cipher or correctly drop the handshake:
```python
# Pass 2: Probe explicitly for legacy weak ciphers
weak_ctx = ssl.create_default_context()
weak_ctx.check_hostname = False
weak_ctx.verify_mode = ssl.CERT_NONE

# CRITICAL FIX: Explicitly disable TLS 1.3 to prevent default secure fallback
weak_ctx.maximum_version = ssl.TLSVersion.TLSv1_2

weak_ctx.set_ciphers("3DES:RC4:DES:MD5:EXPORT")
```

## 7. Final Verdict
**NEEDS REMEDIATION**
The underlying default CVSS architecture is transparent, safe, and accurately labeled. However, the `Legacy Weak TLS Ciphers Supported` probe contains a systemic false positive defect on modern TLS 1.3 servers due to missing protocol bounds on the test context.
