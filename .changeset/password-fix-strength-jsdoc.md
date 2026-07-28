---
"@exortek/password": patch
---

Fix JSDoc on `strength()`/`PolicyRules.denyList` that incorrectly claimed a built-in common-password list check — no such check exists (`Weakness` never included it); the real weaknesses are too-short, single-class, repetition, sequential, and contains-user-info. Docs-only correction, no behavior change.
