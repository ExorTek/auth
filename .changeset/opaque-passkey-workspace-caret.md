---
'@exortek/opaque': patch
'@exortek/passkey': patch
---

Publish sanctioned cross-package edges with a `workspace:^` range instead of
`workspace:*`. The exact pin forced an exact `@exortek/crypto` (and, for
passkey, `@exortek/challenge`) version into consumer trees, which could
duplicate a copy of the dependency; the caret range dedupes to a single shared
install. Aligns both manifests with the range policy in `AGENTS.md`.
