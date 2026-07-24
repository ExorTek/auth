import { createFingerprint, fingerprintRequest } from '@exortek/ua/fingerprint';

// Manual fingerprint creation
const fp = createFingerprint({
  ua: 'Mozilla/5.0 (Linux; Android 14; SM-S911B) AppleWebKit/537.36 Chrome/126.0.0.0 Mobile Safari/537.36',
  headers: {
    'accept-language': 'en-US,en;q=0.9,tr;q=0.8',
  },
  ip: '192.168.1.42',
});

console.log(fp); // 'fp_a8f3b2c1d4e5f6...' (32-char hex after prefix)

// Layers:
// - Stable (always): browser family, OS family, device type
// - Semi-stable (default): browser major, OS version, Accept-Language
// - Volatile (opt-in): IP or subnet

// Stable-only fingerprint (survives browser updates)
const stableFp = createFingerprint(
  {
    ua: 'Mozilla/5.0 ... Chrome/126.0.0.0 ...',
    headers: {},
  },
  { strict: false },
);

// With subnet (IP /24 for IPv4, /64 for IPv6)
const subnetFp = createFingerprint(
  {
    ua: 'Mozilla/5.0 ...',
    headers: {},
    ip: '192.168.1.42',
  },
  { subnet: true },
);

// With full IP (most specific)
const ipFp = createFingerprint(
  {
    ua: 'Mozilla/5.0 ...',
    headers: {},
    ip: '192.168.1.42',
  },
  { includeIP: true },
);

// Express/Fastify shorthand
function middleware(req, res, next) {
  req.fingerprint = fingerprintRequest(req);
  // Uses req.headers['user-agent'], req.headers, req.ip automatically
  next();
}
