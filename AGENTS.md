# AGENTS.md — Project Instructions

## Core Goal
Minimize AI token/context usage while making safe, targeted changes to this website security scanner/SaaS project.

## Rules

- Inspect only files relevant to the current task.
- Reuse existing code, utilities, components, and patterns before creating new ones.
- Make the smallest targeted change that fully solves the task.
- Do not perform broad refactoring unless explicitly requested.
- Do not add unnecessary dependencies.
- Do not change existing functionality, architecture, UI behavior, detection logic, scoring, or user changes unless the task requires it.
- Preserve backward compatibility where practical.
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

- Run only tests and checks relevant to the changed functionality.
- For security scanner changes, verify the affected detection/reporting behavior.
- Run a build when frontend/build files are changed.
- Run targeted tests when backend/scanner logic is changed.
- Use browser testing when the task affects UI and browser testing is available.
- Use broader regression tests only when the change has meaningful cross-module impact.

## Workflow

Follow:

`Locate → Understand → Minimal implementation → Verify → Review → Brief report`

Before changing code:
- Identify the smallest set of relevant files.
- Understand the existing implementation.
- Check for existing utilities/components that can be reused.

After changing code:
- Verify only what is relevant.
- Check that no unrelated behavior was changed.
- Review the final diff when appropriate.

## Security Scanner Requirements

- Preserve passive/authorized scanning behavior unless explicitly instructed otherwise.
- Never introduce active exploitation or destructive testing.
- Maintain SSRF protections for all user-supplied URLs.
- Do not expose secrets, credentials, API keys, or internal infrastructure details.
- Preserve finding detection accuracy, evidence, severity, scoring, and report structure unless explicitly requested to change them.

## Removal Requirements

When a feature or API is intentionally removed:
- Remove its implementation.
- Remove unused imports.
- Remove related dependencies if no longer required.
- Remove related environment variables/configuration.
- Remove related UI/routes/components.
- Remove obsolete tests only when they test functionality that no longer exists.
- Search for remaining references before considering the removal complete.

## Final Response

After completing a task, report only:

**Changed:** Brief summary  
**Verified:** Tests/build/browser checks actually performed  
**Issues:** Any remaining issue, or `None`

Keep the response concise.

## Tool/Agent Compatibility

These instructions should be followed consistently by Antigravity, Cursor, Windsurf, Claude Code, Codex, GitHub Copilot, and similar coding agents.
