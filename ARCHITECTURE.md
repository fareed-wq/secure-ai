# Project Architecture

Secure-AI utilizes a decoupled architecture combining a modern React frontend with a high-performance Python serverless backend engine.

## Frontend Architecture
- **Framework:** React 19 built with Vite.
- **Routing:** React Router handles client-side navigation (`/`, `/scanner`, `/dashboard`, etc.).
- **Styling & Theming:** TailwindCSS combined with a custom CSS-variable inversion system. The `.light-theme` class shifts semantic color bindings (like `slate-800` mapping to `slate-300`) to guarantee pixel-perfect Dark and Light layouts without duplicating JSX classes.
- **State Management:** React hooks and component-level state for scanning operations.
- **Visualization:** Recharts for security score plotting and metric visualization.

## Backend / API Architecture
- **Serverless Hosting:** Vercel. `vercel.json` intercepts all `/api` and `/scan` traffic, routing it to `api/index.py`.
- **Framework:** FastAPI handles REST endpoints (`/api/scan`, `/api/scan/batch`), CORS, and rate limiting (via client IP tracking).
- **Execution Model:** `asyncio` combined with `ThreadPoolExecutor` ensures that heavy blocking network I/O from scanner modules runs concurrently, respecting the 45-second Vercel serverless timeout.

## Scanner Engine (`api/scanner/`)
- **Orchestrator (`orchestrator.py`):** Accepts a URL, canonicalizes it, fetches metadata (IP, WHOIS, liveness), and spawns concurrent threads for every registered scanner module.
- **Transport (`transport.py`):** A custom HTTP session wrapper that enforces safe request headers, blocks cookies, disables TLS verification (for testing), and enforces strict SSRF protections (blocking local IPs and localhost resolution).
- **Scoring Pipeline (`scoring.py`):** Receives the aggregated raw findings and:
  - Deduplicates findings to prevent penalty stacking.
  - Computes a letter grade (A+ to F) based on a weighted penalty scale (Critical=100, High=30, etc.).
  - Auto-assigns compliance impact mapping (NIST, PCI-DSS, ISO27001).

## Reporting Pipeline
1. The raw JSON output from the backend is received by the frontend `Scanner.jsx`.
2. **Simple Report:** Renders a high-level executive summary, letter grade, and business risk categories (using `translations.js` for styling severity).
3. **Technical Report:** Renders deep technical evidence, raw JSON payloads, configuration details, and server-specific remediation snippets (`RemediationSnippetBox.jsx`).

## Major Dependencies
- **Supabase JS:** Client-side database communication and authentication.
- **html2pdf.js / html2canvas / jspdf:** Used for converting the rendered DOM report into downloadable PDF artifacts.
- **FastAPI / urllib3:** Backend request handling and raw transport mechanics.
