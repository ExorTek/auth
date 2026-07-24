---
'@exortek/security': patch
---

Add `formField` option to CSRF middleware, decoupling the form `<input name="…">` from the cookie name. Defaults to `cookieName` for backwards compatibility.
