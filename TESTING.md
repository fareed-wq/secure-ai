# Testing Strategy

## Principles
- **Proportional Verification:** Verification should be proportional to the blast radius of the change.
- **Targeted First:** Always begin with targeted tests directly relevant to the modified code.
- **Broader Regression:** Run broader regression tests only when shared or cross-module code changes.
- **Realistic Mocks:** Tests must model actual production behavior. Mocks must remain realistic.
- **Test Integrity:** Never weaken or delete tests merely to get a green suite. Understand why a test fails before modifying it.

## Verification Matrix

**Frontend-only change:**
- Relevant UI inspection/test
-
pm run build
- git diff --check

**Schedule API / backend change:**
- 	ests/test_schedules.py
- Compile relevant backend files
- Frontend build only when frontend is affected

**Scheduled email / PDF change:**
- 	ests/test_scheduled_email.py
- 	ests/test_scheduled_email_worker.py
- 	ests/test_schedules.py when integration is affected
- Compile backend
- Frontend build if Schedule UI changed

**Scanner module change:**
- Affected module tests
- Relevant scanner regression tests
- Scoring/reporting tests if output changes

**Shared scanner / scoring / orchestrator change:**
- Broader relevant scanner regression suite

**Migration / schema change:**
- Migration review (nullability, constraints, RLS)
- Schema compatibility check
- Relevant API tests
- Production application verification (separate from code tests)

## Required Completion Checks
When relevant, ensure the following checks are performed before completing a task:
- git diff --check
- git diff --stat
- git status --short
- Inspect final diff

## Production Bug Regression Rule
Every confirmed production bug should receive a regression test reproducing the actual failure mode when practical.

Conceptual examples:
- Malformed PostgREST filter
- Transient entitlement lookup
- False
un_not_found
- Idempotency / lease behavior
