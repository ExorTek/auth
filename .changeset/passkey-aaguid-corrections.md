---
'@exortek/passkey': patch
---

Correct and expand the built-in AAGUID → authenticator-name baseline (`@exortek/passkey/aaguid`), verified against the Passkey.dev community list.

Two entries were wrong:

- `d548826e-79b4-db40-a3d8-11116f7e8349` is **Bitwarden**, not "Google Password Manager (Android)" — a real Bitwarden passkey was reported under the wrong name (and no such Google AAGUID exists).
- `d197a58d-4c07-4cff-8180-4e6c8fdd9c05` was labelled "Bitwarden" but is not Bitwarden's AAGUID; removed.

Also renamed `fbfc3007-…` from "iCloud Keychain" to its current name **Apple Passwords**, and added six common providers: Bitwarden, Dashlane, Keeper, NordPass, Samsung Pass, Chrome on Mac, Edge on Mac.
