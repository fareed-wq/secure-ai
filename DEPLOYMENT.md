# Deployment

## Environments
- **dev branch:** Integration branch / PR source.
- **main branch:** Production branch.
- **Vercel Preview:** Branch/PR previews when available.
- **Vercel Production:** Main production deployment.

**Workflow:** dev → Pull Request → main → Vercel Production Deployment

## Services
- **Vercel:** Frontend delivery and FastAPI serverless execution.
- **Supabase:** Postgres database, Row Level Security (RLS), and user authentication.
- **QStash:** Serverless message queue for scheduling (recurring scans and one-time email jobs).
- **Resend:** Transactional email delivery.

## Environment Variables
*Note: This document contains variable NAMES only. Never commit actual secret values.*
*Note: The .env.example file in the repository may be stale and missing several of these production variables.*

### Application
- APP_BASE_URL (Required Production)

### Supabase
- VITE_SUPABASE_URL (Frontend Public)
- VITE_SUPABASE_ANON_KEY (Frontend Public)
- SUPABASE_SECRET_KEY (Required Production)

### QStash
- QSTASH_TOKEN (Required Production)
- QSTASH_CURRENT_SIGNING_KEY (Required Production)
- QSTASH_NEXT_SIGNING_KEY (Required Production)
- QSTASH_URL (Optional / Local override)

### Resend
- RESEND_API_KEY (Required Production)

## Canonical Production URL
https://www.urlscanonline.com

## Database Migration Procedure
1. Review the migration file (nullability, constraints, foreign keys, RLS, defaults).
2. Confirm the target environment.
3. Verify whether the migration has already been applied.
4. Apply using the approved production mechanism.
5. Verify resulting columns, constraints, defaults, and RLS behavior.
6. Deploy dependent code as appropriate.
7. Perform targeted production verification.

**Explicit Rule:** A local migration file existing does NOT mean the production migration has been applied. Do not rerun migrations blindly.

## QStash
- **Recurring Scheduled Scan:** Retries set to 0 to avoid runaway repeated executions.
- **One-Time Email Job:** Retries set to 3.
- **Signature Keys:** Verifies the origin of the webhook via QSTASH_CURRENT_SIGNING_KEY / QSTASH_NEXT_SIGNING_KEY.
- **Targeting:** Requires a canonical APP_BASE_URL for webhook resolution.

## Resend
- **API Key:** Maintained strictly server-side.
- **Recipient:** Target is restricted to the current verified account recipient.
- **Idempotency:** Email delivery utilizes idempotency keys (e.g., scheduled-report-<run_id>) to prevent duplicate sends.

## Rollback / Failure Safety
- **Deployments:** An application deploy rollback does not automatically rollback a database migration.
- **Schema Compatibility:** Always consider schema backward compatibility before deployment.
- **Failure Isolation:** Temporary third-party failures (e.g. entitlement lookup timeout) should fail gracefully and avoid creating a destructive permanent state (like permanently deleting or disabling a schedule).
