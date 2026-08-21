# Secure-AI Web Scanner

Secure-AI is an advanced, non-intrusive web security posture checker. It provides rapid, modular security scanning of public web properties directly from the browser by utilizing a serverless Python scanning engine.

## Purpose
The platform enables developers, security engineers, and site owners to quickly assess the security posture of their web applications. It focuses exclusively on **passive** detection mechanisms—identifying misconfigurations, missing best practices, and exposed information without sending intrusive payloads or exploiting vulnerabilities.

## Features
- **Modular Scanning Engine:** Rapid, multi-threaded checks for DNS, TLS, HTTP headers, discovery, and API configurations.
- **Comprehensive Reporting:** Provides a Simple Report (business risk, letter grades) and a Technical Report (detailed evidence, remediation snippets).
- **Compliance Mapping:** Maps findings to major compliance frameworks including OWASP Top 10, PCI-DSS 4.0, NIST SP 800-53, and ISO 27001.
- **Responsive Theme:** Features a premium UI with identical structural layouts across fully independent Dark and Light modes.
- **History & Auth:** Integrates with Supabase for user authentication and historical scan retention.
- **Export Capabilities:** Export detailed reports to PDF.

## Technology Stack
- **Frontend:** React 19, Vite, TailwindCSS (Arbitrary Variable Theming), Framer Motion, Recharts.
- **Backend (Scanner Engine):** Python 3.9+, FastAPI (deployed as Vercel Serverless Functions).
- **Database & Auth:** Supabase.
- **Deployment:** Vercel.

## Installation & Development
1. Clone the repository.
2. Install frontend dependencies:
   ```bash
   npm install
   ```
3. Set up environment variables (copy `.env.example` to `.env` and fill in Supabase credentials).
4. Run the frontend development server:
   ```bash
   npm run dev
   ```

*Note: The backend requires a Vercel environment or a local FastAPI uvicorn runner for the `/api` routes to function properly outside of Vercel.*

## Build
```bash
npm run build
```

## Current Limitations
- **Passive Only:** Secure-AI does not perform active vulnerability exploitation (e.g., SQLi, XSS payload injection) and cannot replace authenticated dynamic application security testing (DAST).
- **Rate Limiting:** Scans are limited to a maximum of 10 scans per minute per IP address.
- **Serverless Timeouts:** Deep scanning features (like subdomain enumeration) are bounded by Vercel serverless execution timeouts (typically 45-60 seconds max).
