# URLScannerOnline

URLScannerOnline (internally known as Secure-AI) is an advanced web security posture checker. It provides rapid, modular security scanning of public web properties by utilizing a serverless Python scanning engine.

## Overview
The platform enables developers, security engineers, and site owners to quickly assess the security posture of their web applications. It focuses on identifying misconfigurations, missing best practices, and exposed information.

## Features
- **Basic Scan:** Passive assessment relying on metadata analysis and known-path discovery.
- **Advanced Scan:** Authorized, low-impact scans performing bounded HTTP/DNS/TCP checks without active exploitation.
- **Scheduled Scans:** Set scans to run on a Daily, Weekly, or Monthly basis using IANA timezone scheduling.
- **Reporting:** Simple and Technical reports available for browser viewing.
- **Scheduled Emails:** Optional email report delivering a safe executive summary alongside one combined scheduled email PDF.
- **Scan History:** Integrates with Supabase for user authentication and historical scan retention.

## Basic vs Advanced
- **Basic:** Strictly passive. Ideal for safe, rapid reconnaissance without impacting the target.
- **Advanced:** Ad-hoc Advanced scans require explicit authorization acknowledgement. Scheduled Advanced scans require recurring authorization acknowledgement. Remains passive-first and low-impact, explicitly avoiding brute force, DoS, and exploit payloads.

## Scheduled Scans
Schedule Scans currently supports up to 3 recurring schedules per eligible account and is presently restricted to admin access. (Broader paid access is future/not live). Schedules are executed reliably via QStash and are fully DST-aware using IANA timezone rules.

## Reporting
The system generates a high-level Simple Report (business risk, letter grades) and an in-depth Technical Report (detailed evidence, remediation snippets). For scheduled scans, a combined deterministic PDF containing both executive and technical details is generated server-side.

## Technology Stack
- **Frontend:** React 19, Vite, TailwindCSS, Framer Motion, Recharts.
- **Backend (Scanner Engine):** Python 3.9+, FastAPI (deployed as Vercel Serverless Functions).
- **Database & Auth:** Supabase.
- **Scheduling & Email:** QStash, Resend, ReportLab.
- **Deployment:** Vercel.

## Local Development
1. Clone the repository.
2. Install frontend dependencies:
   `ash
   npm install
   `
3. Set up environment variables (copy .env.example to .env and fill in Supabase credentials).
4. Run the frontend development server:
   `ash
   npm run dev
   `

*Note: The backend requires a Vercel environment or a local FastAPI uvicorn runner for the /api routes to function properly outside of Vercel.*

## Security & Responsible Use
URLScannerOnline enforces strict SSRF protections and public-target validation. Users are responsible for verifying findings and responsibly disclosing discovered vulnerabilities. The scanner will never perform active vulnerability exploitation (e.g., SQLi, XSS payload injection).

## Documentation
- [AGENTS.md](AGENTS.md) - AI agent workflow, regression prevention, Git discipline
- [ARCHITECTURE.md](ARCHITECTURE.md) - System components, data flows, and invariants
- [SCANNER.md](SCANNER.md) - Basic/Advanced scanner behavior and modules
- [SECURITY.md](SECURITY.md) - Security boundaries, authorization, and privacy
- [TESTING.md](TESTING.md) - Test/verification strategy
- [DEPLOYMENT.md](DEPLOYMENT.md) - Production services, config, migrations, deployment

## Current Limitations
- **No Authenticated Application Scanning:** URLScannerOnline does not traverse authenticated routes or login portals.
- **Rate Limiting:** Scans are limited to a maximum of 10 scans per minute per IP address.
- **Serverless Timeouts:** Deep scanning features are bounded by Vercel serverless execution timeouts (enforced by a 45-second execution budget).
