# Phase 32 Overlap Report

## 1. JSBundleSecretsModule vs JavaScriptSecurityModule
**Files:** pi/scanner/modules/content.py, pi/scanner/modules/javascript_security.py
**Description:** Both modules fetch HTML, extract <script> tags, download the primary JS bundles, and run regex patterns to identify secrets and source maps. JSBundleSecretsModule distinguishes between private (high) and public (informational) keys, while JavaScriptSecurityModule only has a general list.
**Action Taken:** JSBundleSecretsModule will be deleted, and its key categorizations (PRIVATE_SECRET_PATTERNS, PUBLIC_KEY_PATTERNS) will be integrated into JavaScriptSecurityModule.

## 2. SensitivePathsModule vs OpenApiModule & RobotsTxtModule
**Files:** pi/scanner/modules/content.py, pi/scanner/modules/discovery.py
**Description:** SensitivePathsModule probes /swagger.json and /admin. OpenApiModule also probes /swagger.json. RobotsTxtModule checks for /admin in robots.txt.
**Action Taken:** SensitivePathsModule will be deleted to reduce duplicate network requests for /swagger.json. The /admin probe will be incorporated into a lightweight logic inside ExposedFilesModule or left out since login pages are already detected heuristically across the site.
