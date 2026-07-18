---
'@exortek/security': patch
---

`getClientIp` walks `X-Forwarded-For` **right-to-left** when
`trustProxy` is an allowlist, returning the first untrusted hop instead
of the left-most entry. The old behaviour was spoofable: an attacker
could send their own `X-Forwarded-For: 1.2.3.4` header, a conforming
proxy would *append* the real address, and `trustProxy: ['proxy-ip']`
still returned the attacker-controlled left-most value — bypassing
rate-limit keys, poisoning IP logs, and misleading fingerprint binding.

Also new: `proxyCount: N` skips **N** rightmost hops and returns the
`(N + 1)`-th from the right — an addresses-not-known alternative to
`trustProxy: string[]` for setups like Cloudflare + a k8s ingress.
`proxyCount` wins over `trustProxy` when both are set.

`trustProxy: true` keeps its left-most behaviour for backwards
compatibility but is now documented as unsafe unless the first proxy
strips inbound XFF headers — prefer `trustProxy: string[]` or
`proxyCount` in production.
