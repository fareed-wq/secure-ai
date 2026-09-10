# Project Architecture

URLScannerOnline (Secure-AI) utilizes a decoupled architecture combining a modern React frontend with a high-performance Python serverless backend engine.

## Architecture Diagram

`
User
  |
React/Vite
  |
FastAPI
  |-- Scanner
  |     |-- Basic
  |     -- Advanced
  |
  |-- Supabase
  |
  |-- QStash recurring scan
  |
  |-- QStash one-time email
  |
  |-- ReportLab
  |
  -- Resend
`

## Repository Structure
- src/ — React frontend application code
- pi/ — FastAPI serverless backend
- pi/scanner/ — Core scanning engine and modules
- pi/scheduling/ — Schedule API, workers, and QStash endpoints
- supabase/migrations/ — Database schema definitions
- 	ests/ — Automated test suite
- docs/audits/ — Historical verification and remediation artifacts
- .agents/ — AI coding agent skills and instructions

## Frontend Architecture
- **Framework:** React 19 built with Vite.
- **Routing:** React Router handles client-side navigation (/, /scanner, /dashboard, etc.) and auth-aware UI.
- **Styling & Theming:** TailwindCSS combined with a custom CSS-variable inversion system. The .light-theme class shifts semantic color bindings to guarantee pixel-perfect Dark and Light layouts without duplicating JSX classes.
- **State Management:** React hooks and component-level state for scanning operations.
- **Visualization:** Recharts for security score plotting and metric visualization.
- **Reporting:** Renders Simple and Technical reports in the browser.

## Backend / API Architecture
- **Serverless Hosting:** Vercel. ercel.json intercepts all traffic, routing it to pi/index.py or the frontend.
- **Framework:** FastAPI handles REST endpoints, CORS, and rate limiting.
- **Execution Model:** syncio combined with ThreadPoolExecutor ensures that heavy blocking network I/O from scanner modules runs concurrently, respecting the global 45-second execution budget (SCAN_BUDGET_SECONDS).
- **Internal Workers:** Secured endpoints for background jobs initiated by QStash.

## Supabase (Database & Auth)
- **Auth:** Manages user sessions and identity.
- **Postgres:** Relational database backing the application.
- **RLS (Row Level Security):** Enforces owner-scoped access by default, with only explicitly designed sharing/access paths or privileged internal workers allowed.
- **Key Tables:**
  - profiles: User information and settings.
  - scans: Ad-hoc scan history.
  - saved_reports: Persistent snapshots of specific reports.
  - scan_schedules: Definitions for recurring scheduled scans.
  - scheduled_scan_runs: History and state of each executed scheduled scan.

## Scanner Engine (pi/scanner/)
- **Basic Scan:** Passive modules only. Focuses on information disclosure, headers, and metadata.
- **Advanced Scan:** Authorized, bounded active modules. Low-impact checks that include all Basic checks plus deeper HTTP/DNS/TCP analysis.
- **Orchestrator (orchestrator.py):** Canonicalizes URLs, fetches metadata, and spawns concurrent threads for registered scanner modules.
- **Scoring Pipeline (scoring.py):** Deduplicates findings, computes a letter grade (A+ to F), and assigns compliance mappings.

## Schedule Scans & State Invariants
- **Current Access:** Schedule Scans are currently restricted to admin access. (Broader paid entitlements are future/not live).
- **Limits:** Maximum 3 schedules per user TOTAL (across Basic and Advanced).
- **Frequency:** Supports Daily, Weekly, and Monthly recurrences. (No arbitrary cron exposed to users).
- **Timezone:** Uses valid IANA timezone identifiers (default Asia/Riyadh), supporting DST-aware IANA recurrence behavior.
- **Scan Modes:** Supports both Basic and Advanced scheduled scans.

**State & Execution:**
- scan_schedules maintains the recurring schedule definition.
- scheduled_scan_runs maintains the immutable historical execution record and independent email-delivery state.
- **Entitlement Tri-State:** Eligibility uses three semantic outcomes: ELIGIBLE (continue), INELIGIBLE (may pause/disable schedule), and ERROR (temporary inability to determine eligibility). An ERROR must NOT be treated as INELIGIBLE and does not permanently disable the DB schedule. Since QStash retries=0 for scheduled scans, an ERROR may cause the current occurrence to be missed, but future recurrence remains active.
- **Email Delivery States:** Stable states include
ot_requested, pending, sending, sent, and ailed.
- **Decoupled Success:** A completed scan's status is independent of its email delivery status. An email failure must not convert a completed scan into a failed scan.
- **Historical Preservation:** Schedule deletion must not destroy completed run history; scheduled_scan_runs.schedule_id may be NULL after schedule deletion.

## QStash (Scheduling)
- **Recurring Scheduled Scan:** Direct recurring QStash schedule triggering /api/internal/scheduled-scan.
- **One-Time Report Email:** Triggered after a scan completes successfully, hitting /api/internal/scheduled-report-email.

## Reporting Pipeline
- **Frontend Simple PDF:** Browser-generated executive summary.
- **Frontend Technical PDF:** Browser-generated deep technical report.
- **Server ReportLab PDF:** Backend-generated combined (Executive + Technical) PDF for scheduled email reports.
  - Generates exactly one combined attachment from the exact persisted scan snapshot.
  - Does not rescan or fetch external data.
  - Deterministic generation with no permanent PDF storage.
  - Internal 10 MB attachment cap (an oversized report fails email delivery without changing the completed scan status).

## Email (Resend)
- **Transactional Email:** Handled via Resend API, sending safe executive summaries and attaching the ReportLab PDF.

## System Invariants
- **Persisted scan is authoritative:** The scheduled email report relies entirely on the persisted scan snapshot.
- **No rescanning for email:** The scheduled email job does not rescan the target or fetch external data.
- **Separation of concerns:** Scan success and email success are tracked independently in scheduled_scan_runs.
- **Server-side authorization is authoritative:** The API enforces permissions regardless of UI state.
- **Opaque Identifiers:** QStash messages contain opaque identifiers only (e.g., schedule_id,
un_id).
- **SSRF Validation:** Network requests strictly enforce public-target validation and SSRF protection.
