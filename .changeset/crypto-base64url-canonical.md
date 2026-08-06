---
'@exortek/crypto': minor
---

`base64url.decode` now rejects non-canonical input.

Node ignores the unused low bits of a final base64url character, so several
distinct strings decoded to identical bytes — `'aGVsbG8'`, `'aGVsbG9'`,
`'aGVsbG-'` and `'aGVsbG_'` all produced `"hello"`. Anything keyed on the
encoded form, such as a deny list, a dedupe set or a replay cache, would treat
one value as several.

`decode` now accepts only the canonical spelling of the bytes and raises
`INVALID_ENCODING` otherwise. Padding is still accepted, and anything produced
by `base64url.encode` still round-trips.

**This is a behaviour change.** Input your callers previously got bytes back
for may now throw. If you accept base64url from an external source and want the
old leniency, re-encode from the decoded bytes before comparing.
