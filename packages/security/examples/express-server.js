// Express security middleware demo.
//
//   node packages/security/examples/express-server.js
//
// Then in another terminal:
//
//   curl -i http://127.0.0.1:3000/ping
//   curl -i -X OPTIONS -H 'origin: https://app.example.com' \
//     -H 'access-control-request-method: POST' http://127.0.0.1:3000/api/echo
//   for i in {1..12}; do curl -s -o /dev/null -w "%{http_code}\n" \
//     http://127.0.0.1:3000/ping; done   # last few should be 429
//
// Requires: `yarn workspace @exortek/security add express cookie-parser` in dev.

import express from 'express';
import cookieParser from 'cookie-parser';
import { rateLimit } from '../src/index.js';
import { securityMiddleware } from '../src/middleware/express.js';

const SECRET = 'x'.repeat(32); // demo only — read from env in prod

const app = express();
app.set('trust proxy', true);
app.use(express.json());
app.use(cookieParser());

app.use(
  securityMiddleware({
    headers: {}, // sensible defaults (HSTS, X-Content-Type-Options, ...)
    cors: { origin: ['https://app.example.com'] },
    csrf: { secret: SECRET },
    rateLimit: {
      limiter: rateLimit.sliding({
        requests: 10,
        window: '1m',
        store: rateLimit.stores.memory(),
      }),
    },
  }),
);

app.get('/ping', (_req, res) => res.json({ ok: true }));
app.post('/api/echo', (req, res) => res.json({ echo: req.body ?? null, csrf: req.csrfToken?.() }));

const port = Number(process.env.PORT) || 3000;
app.listen(port, () => console.log(`express security demo → http://127.0.0.1:${port}`));
