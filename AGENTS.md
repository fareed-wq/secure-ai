# AGENTS.md — Project Instructions

## Core Goal
Minimize AI token/context usage while making safe, targeted changes to this website security scanner/SaaS project.

## Rules
- Understand current behavior before modifying it.
- Inspect the smallest relevant scope first.
- Reuse existing code, utilities, components, and patterns before creating new ones.
- Make the smallest targeted change that fully solves the task.
- Do not perform broad refactoring unless explicitly requested.
- Avoid unrelated refactors.
- Do not add unnecessary dependencies.
- Preserve unrelated behavior.
- Preserve security and architecture invariants.
- Preserve API/database backward compatibility where practical.
- Keep API keys, credentials, and secrets server-side.
- Follow secure coding practices, especially SSRF protection for URL/website scanning.
- When removing a feature, also remove its related code, dependencies, environment variables, configuration, and UI when no longer needed.
- Do not duplicate existing functionality.
- Do not invent missing requirements; ask only when genuinely necessary.
- Never claim a test, scan, build, or browser check was performed unless it actually was.

## Efficiency
Prioritize:
1. Targeted inspection
2. Minimal implementation
3. Targeted verification
4. Review
5. Concise report

Avoid:
- Full-project analysis when unnecessary
- Reading unrelated files
- Rewriting working code
- Unnecessary refactoring
- Unnecessary dependencies
- Repeating existing logic
- Long explanations

## Verification
- Consider blast radius when choosing verification.
- Run only tests and checks relevant to the changed functionality.
- Shared/core changes require relevant broader regression coverage.
- Frontend changes require build verification where appropriate (
pm run build).
- Run git diff --check before completion.
- Inspect final diff.
- Green tests alone do not prove correctness. Verify that tests actually cover the requested behavior.
- Never claim verification that was not performed.
- For security scanner changes, verify the affected detection/reporting behavior.

## Test Integrity
- Never delete a failing test merely to make the suite pass.
- Never weaken assertions merely to get green tests.
- Never skip/disable tests without explicit justification.
- Determine whether a failure comes from: production code, test assumptions, mocks, environment, or stale expected behavior.
- When fixing a production bug, add a regression test reproducing the actual failure mode when practical.
- Mocks must represent realistic production behavior.
- Security/idempotency/auth/lease/retry/persistence tests are regression guards.
- Do not replace a meaningful test with a superficial implementation-detail assertion.

## Git Safety
- Never use git add .
- Never use git add -A
- Stage intended files explicitly.
- Inspect diff before staging.
- Inspect cached diff before commit.
- Preserve unrelated tracked and untracked files.
- Do not commit unless explicitly requested.
- Do not push unless explicitly requested.
- Do not merge main unless explicitly requested.
- Do not force-push without explicit approval.
- Do not destructive-reset/rebase without explicit approval.
- Do not reuse known untracked filenames as temporary helper scripts.

## Merge Conflict Safety
- Never blindly resolve with --ours or --theirs.
- Inspect both sides.
- Resolve semantically.
- Preserve useful implementation changes from both sides.
- Preserve valid tests from both sides.
- Search for conflict markers after resolution.
- Rerun tests affected by conflicted files.
- If wholesale ours/theirs is intentionally selected, audit the discarded side before completing the merge.

## Database / Migration Safety
- Never rerun production migrations blindly.
- Migration file existing locally does not prove production migration applied.
- Verify migration state before depending on new schema.
- Do not mutate production data merely to make a test pass.
- Review: nullability, foreign keys, RLS, indexes, defaults, existing-row compatibility.
- Server-side/database authorization remains authoritative. Client UI restrictions are never sufficient authorization.
- Production migration application must be explicitly confirmed.
- Avoid destructive schema/data changes unless explicitly approved.

## Error Classification
- Do not collapse infrastructure errors into valid business states.
- Distinguish: success, not-found, ineligible, contention, transient failure, permanent failure.
- Temporary backend failure must not create permanent user/account state unless intentionally designed.

## Temp Script Safety
- Prefer direct small edits.
- If a temporary helper script is necessary, give it a unique task-specific name.
- Delete only scripts created by the current task.
- Never overwrite/reuse pre-existing untracked helper files.

## Workflow
Follow: Locate -> Understand -> Minimal implementation -> Verify -> Review -> Brief report

Before changing code:
- Identify the smallest set of relevant files.
- Understand the existing implementation.
- Check for existing utilities/components that can be reused.

After changing code:
- Verify only what is relevant.
- Check that no unrelated behavior was changed.
- Review the final diff when appropriate.

## Security Scanner Requirements
- Preserve passive-first/low-impact scanning behavior unless explicitly instructed otherwise.
- Never introduce active exploitation or destructive testing.
- Maintain SSRF protections for all user-supplied URLs.
- Do not expose secrets, credentials, API keys, or internal infrastructure details.
- Preserve finding detection accuracy, evidence, severity, scoring, and report structure unless explicitly requested to change them.

## Final Response
After completing a task, report only:
**Changed:** Brief summary
**Verified:** Tests/build/browser checks actually performed
**Issues:** Any remaining issue, or None

Keep the response concise.

## Tool/Agent Compatibility
These instructions should be followed consistently by Antigravity, Cursor, Windsurf, Claude Code, Codex, GitHub Copilot, and similar coding agents.
