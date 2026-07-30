# @exortek/ua

> High-performance User-Agent parser for Node.js 22+ — browser, OS, device, engine, CPU detection + bot/AI crawler taxonomy + Client Hints + request fingerprinting. Zero-dependency, tree-shakeable.

[![npm](https://img.shields.io/npm/v/@exortek/ua.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/ua)
[![tests](https://github.com/ExorTek/auth/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/ExorTek/auth/actions/workflows/ci.yml)
[![node](https://img.shields.io/node/v/@exortek/ua.svg?color=339933)](https://nodejs.org)
[![install size](https://packagephobia.com/badge?p=@exortek/ua)](https://packagephobia.com/result?p=@exortek/ua)
[![types](https://img.shields.io/badge/types-included-3178C6)](./dist/index.d.ts)
[![zero-deps](https://img.shields.io/badge/dependencies-0-brightgreen)](./package.json)
[![license](https://img.shields.io/npm/l/@exortek/ua.svg?color=blue)](./LICENSE)

A full-featured UA parser with 60+ browsers, 30+ operating systems, 150+ device
models across phones, tablets, TVs, consoles, XR headsets, vehicles, wearables,
and IoT — plus a bot taxonomy that classifies AI crawlers, search engines,
scrapers, and monitoring tools by category and confidence. Client Hints are
handled transparently, and request fingerprinting gives you stable visitor
identity without cookies.

📖 **Docs:** [**auth.memet.dev/ua**](https://auth.memet.dev/ua)

## Why

The UA-parsing space has a few established players and each leaves gaps:

- **`ua-parser-js`** — 10M downloads/week, good browser coverage, but no
  bot taxonomy, no Client Hints, no fingerprinting, no middleware, and the
  v2 paywall fragmented the community.
- **`bowser`** — clean API but abandoned since 2021, no new browsers or
  device types, no bot detection, no Client Hints.
- **`useragent`** — regex-file-based, slow to update, no structured bot
  classification, no modern device categories (XR, vehicles, IoT).
- **`isbot`** — bot detection only, no parsing. Good at what it does but
  you still need a second library for everything else.

`@exortek/ua` ships everything — parsing, bot taxonomy, Client Hints,
fingerprinting, and framework middleware — in one zero-dep package with
an LRU cache, keyword pre-filters, and lazy getters for performance.

## Install

```bash
npm install @exortek/ua
```

Requires **Node.js 22 or newer**. Zero runtime dependencies.

## Quick start

```js
import { parse } from '@exortek/ua';

const result = parse('Mozilla/5.0 (Linux; Android 14; SM-S911B) ...');

console.log(result.browser.name);   // 'Chrome'
console.log(result.os.name);        // 'Android'
console.log(result.device.type);    // 'mobile'
console.log(result.device.vendor);  // 'Samsung'
console.log(result.engine.name);    // 'Blink'
```

Bot detection:

```js
import { detectBot, isAICrawler } from '@exortek/ua/bots';

const bot = detectBot('GPTBot/1.2');
console.log(bot.category);    // 'ai-training'
console.log(bot.confidence);  // 'medium'

isAICrawler('GPTBot/1.2');    // true
```

## Modules

| Subpath | Purpose |
| --- | --- |
| [`@exortek/ua`](https://github.com/ExorTek/auth/blob/master/packages/ua/src/index.js) | `parse`, `parseBrowser`, `parseOS`, `parseDevice`, `parseEngine`, `parseCPU`, `satisfies`, `isFrozenUA`, `clearCache`, `ACCEPT_CH`, `VARY_CH`, `BOT_CATEGORY` |
| [`@exortek/ua/bots`](https://github.com/ExorTek/auth/blob/master/packages/ua/src/bots.js) | `detectBot`, `isBot`, `isAICrawler`, `isAIAssistant`, `isSearchBot`, `isSocialPreview`, `isSEOBot`, `isSecurityScanner`, `isAutomation`, `createBotDetector`, `clearBotCache`, `BOT_CATEGORY` |
| [`@exortek/ua/fingerprint`](https://github.com/ExorTek/auth/blob/master/packages/ua/src/fingerprint.js) | `createFingerprint`, `fingerprintRequest` |
| [`@exortek/ua/middleware/express`](https://github.com/ExorTek/auth/blob/master/packages/ua/src/middleware/express.js) | `uaMiddleware` — Express middleware |
| [`@exortek/ua/middleware/fastify`](https://github.com/ExorTek/auth/blob/master/packages/ua/src/middleware/fastify.js) | `uaPlugin` — Fastify plugin |
| [`@exortek/ua/middleware/bot-guard`](https://github.com/ExorTek/auth/blob/master/packages/ua/src/middleware/bot-guard-express.js) | `botGuard` — Express bot filter |
| [`@exortek/ua/middleware/bot-guard/fastify`](https://github.com/ExorTek/auth/blob/master/packages/ua/src/middleware/bot-guard-fastify.js) | `botGuardPlugin` — Fastify bot filter |

## API

### `parse(ua, options?)`

```ts
parse(ua: string, options?: {
  headers?: Record<string, string>;
  clientHints?: boolean;  // default: true
}): UAResult
```

Parse a User-Agent string. Returns `{ ua, browser, os, device, engine, cpu }` with lazy getters — sections are only parsed when accessed.

**`browser`** — `{ name, version, major, type }`
**`os`** — `{ name, version }`
**`device`** — `{ type, vendor, model }`
**`engine`** — `{ name, version }`
**`cpu`** — `{ architecture }`

### `parseBrowser(ua)`, `parseOS(ua)`, `parseDevice(ua)`, `parseEngine(ua)`, `parseCPU(ua)`

Parse only one section. Faster when you need a single field.

### `satisfies(result, conditions)`

```ts
satisfies(result: UAResult, conditions: Record<string, string | Record<string, string>>): boolean
```

Check if a parse result matches version conditions:

```js
satisfies(result, { chrome: '>=120', firefox: '>=115' });        // OR logic
satisfies(result, { mobile: { safari: '>=16' } });               // device-scoped
satisfies(result, { desktop: { chrome: '>=120' } });
```

Operators: `>=`, `>`, `<=`, `<`, `=`, `==`, `!=`

### `isFrozenUA(ua)`

```ts
isFrozenUA(ua: string): boolean
```

Returns `true` if the UA string uses Chrome 107+ frozen/reduced format. When true, Client Hints headers are required for accurate version and device info.

### `detectBot(ua)`

```ts
detectBot(ua: string): BotResult | null
```

Returns `{ name, version, type, category, confidence }` or `null`.

**`confidence`**: `'high'` (named + versioned + categorized), `'medium'` (one of those), `'low'` (generic).

### `isBot`, `isAICrawler`, `isSearchBot`, `isSecurityScanner`, `isAutomation`, `isSocialPreview`, `isSEOBot`, `isAIAssistant`

```ts
isBot(ua: string): boolean
isAICrawler(ua: string): boolean
// ... same signature for all
```

Boolean shorthand functions — each calls `detectBot` internally.

### `createBotDetector(extraPatterns)`

```ts
createBotDetector(patterns: Array<{
  pattern: RegExp;
  name: string;
  category?: string;
}>): (ua: string) => BotResult | null
```

Create a detector with custom patterns that fall through to built-in detection:

```js
const detect = createBotDetector([
  { pattern: /mybot\/([\d.]+)/i, name: 'MyBot', category: 'internal' },
]);
```

### `createFingerprint(input, options?)`

```ts
createFingerprint(input: {
  ua: string;
  headers?: Record<string, string>;
  ip?: string;
}, options?: {
  includeIP?: boolean;
  subnet?: boolean;
  strict?: boolean;     // default: true
  algorithm?: string;   // default: 'sha256'
}): string
```

Deterministic hash from request signals:

```js
const fp = createFingerprint({
  ua: req.headers['user-agent'],
  headers: req.headers,
  ip: req.ip,
}, { subnet: true });
// → 'fp_a8f3b2c1...'
```

### `fingerprintRequest(req, options?)`

Shorthand — extracts `ua`, `headers`, `ip` from a request object.

### Express middleware

Global — every route gets `req.ua`:

```js
import { uaMiddleware } from '@exortek/ua/middleware/express';

app.use(uaMiddleware());

app.get('/api', (req, res) => {
  console.log(req.ua.browser.name);
  console.log(req.ua.bot);
});
```

Route-level — only parse where you need it:

```js
import express from 'express';
import { uaMiddleware } from '@exortek/ua/middleware/express';

const app = express();

app.get('/analytics', uaMiddleware(), (req, res) => {
  res.json({
    browser: req.ua.browser.name,
    device: req.ua.device.type || 'desktop',
  });
});

app.get('/health', (req, res) => {
  res.json({ ok: true });
});
```

**Options**:

| Option | Default | Description |
| --- | --- | --- |
| `clientHints` | `true` | Parse Client Hints headers |
| `sendAcceptCH` | `true` | Auto-set `Accept-CH` + `Vary` response headers |
| `detectBots` | `true` | Run bot detection and attach `.bot` to result |
| `property` | `'ua'` | Property name on `req` / `request` |
| `onUnknown(ua)` | — | Called when browser is unrecognized and not a bot |
| `onBot(bot, req)` | — | Called when a bot is detected. Return `true` to block (sends 403) |
| `onParsed(result, req)` | — | Called after parse + bot detection, before `next()` |

```js
app.use(uaMiddleware({
  onBot(bot, req) {
    if (bot.category === 'ai-training') return true; // block → 403
    console.log(`Bot: ${bot.name}`);
  },
  onParsed(result, req) {
    metrics.track('ua', result.browser.name);
  },
}));
```

### Fastify plugin

Global — registers on every route:

```js
import { uaPlugin } from '@exortek/ua/middleware/fastify';

await app.register(uaPlugin, { detectBots: true });

app.get('/', async (request) => {
  console.log(request.ua.browser.name);
});
```

Scoped — register inside an encapsulated context:

```js
import Fastify from 'fastify';
import { uaPlugin } from '@exortek/ua/middleware/fastify';

const app = Fastify();

app.register(async (scope) => {
  await scope.register(uaPlugin);

  scope.get('/analytics', async (request) => {
    return { browser: request.ua.browser.name };
  });
});

app.get('/health', async () => ({ ok: true }));
```

Same options as Express middleware.

### Bot guard middleware

A standalone bot filter — compose it with the UA middleware or use it alone.

```js
import { botGuard } from '@exortek/ua/middleware/bot-guard';

// Block AI training crawlers
app.use(botGuard({ deny: ['ai-training'] }));

// Block everything except search engines
app.use(botGuard({ denyAll: true, allow: ['search'] }));

// Custom callback
app.use(botGuard({
  deny: ['ai-training', 'seo'],
  onBlocked(bot, req) {
    console.log(`Blocked ${bot.name} (${bot.category})`);
  },
}));
```

Fastify:

```js
import { botGuardPlugin } from '@exortek/ua/middleware/bot-guard/fastify';

await app.register(botGuardPlugin, {
  deny: ['ai-training'],
  onBlocked(bot, req) { console.log(`Blocked ${bot.name}`); },
});
```

**Options**:

| Option | Default | Description |
| --- | --- | --- |
| `deny` | — | Bot categories to block |
| `allow` | — | Categories to always allow (overrides `deny` and `denyAll`) |
| `denyAll` | `false` | Block all detected bots |
| `status` | `403` | HTTP status code for blocked requests |
| `onBlocked(bot, req)` | — | Called when a bot is blocked |
| `onAllowed(bot, req)` | — | Called when a bot is allowed through |

## Client Hints

Chrome 107+ sends a reduced/frozen User-Agent — version is locked to `X.0.0.0` and platform info is generalized. Client Hints headers carry the real data.

**If you use the middleware, this is handled for you.** Both `uaMiddleware()` (Express) and `uaPlugin` (Fastify) automatically:

1. Set the `Accept-CH` response header so browsers send high-entropy hints on subsequent requests
2. Read `Sec-CH-UA-*` request headers and merge them into the parse result

No extra configuration needed — `clientHints` and `sendAcceptCH` default to `true`.

**Manual setup** (without middleware):

```js
import { parse, ACCEPT_CH, VARY_CH, isFrozenUA } from '@exortek/ua';

// Step 1: tell the browser which hints you want
res.setHeader('Accept-CH', ACCEPT_CH);
res.setHeader('Vary', VARY_CH);

// Step 2: parse with hints on subsequent requests
const ua = req.headers['user-agent'];
const result = parse(ua, { headers: req.headers });

// isFrozenUA() tells you when hints are critical
if (isFrozenUA(ua)) {
  // result.browser.version, result.device.model etc.
  // come from hints, not the frozen UA string
}
```

**Headers read:** `Sec-CH-UA`, `Sec-CH-UA-Full-Version-List`, `Sec-CH-UA-Mobile`, `Sec-CH-UA-Model`, `Sec-CH-UA-Platform`, `Sec-CH-UA-Platform-Version`, `Sec-CH-UA-Arch`, `Sec-CH-UA-Bitness`, `Sec-CH-UA-Form-Factors`.

## Bot taxonomy

| Category | Examples |
| --- | --- |
| `search` | Googlebot, Bingbot, DuckDuckBot, Baiduspider, YandexBot |
| `ai-training` | GPTBot, Google-Extended, CCBot, Bytespider, Diffbot |
| `ai-assistant` | ChatGPT-User, Perplexity, YouBot |
| `ai-agent` | Claude-Web, Anthropic-AI |
| `social-preview` | Twitterbot, facebookexternalhit, LinkedInBot, Slackbot, WhatsApp, TelegramBot |
| `monitoring` | UptimeRobot, Pingdom, Site24x7, DatadogSynthetics |
| `advertising` | AdsBot-Google, Mediapartners-Google |
| `seo` | AhrefsBot, SemrushBot, MJ12bot, DotBot |
| `security-scanner` | Nessus, Qualys, Nuclei, ZAP |
| `automation` | HeadlessChrome, PhantomJS, Selenium, Puppeteer |
| `archiving` | archive.org_bot, Wayback |
| `feed` | Feedfetcher-Google, Feedly |
| `link-validator` | W3C_Validator, W3C-checklink |
| `payment` | Stripe, PayPal IPN |
| `performance` | Lighthouse, PageSpeed |
| `generic` | Everything else |

## Coverage

### Browsers (60+)

Chrome, Firefox, Safari, Edge, Opera, Brave, Vivaldi, Samsung Internet, UCBrowser, QQBrowser, Arc, Midori, Falkon, Waterfox, Pale Moon, Basilisk, SeaMonkey, Konqueror, Silk, Whale, Naver, Puffin, Epiphany/GNOME Web, Lynx, Links, Dillo, NetSurf, Surf, DuckDuckGo, Yandex, Opera Mini, Firefox Focus, Chrome Headless, Chrome WebView, GSA (Google Search App), Facebook, TikTok, WeChat, Slack, VS Code, Quark, Flip Player, Yahoo! Japan, rad.io, Lighthouse, and more.

In-app: Facebook, Instagram, TikTok, WeChat, Slack, LINE, Snapchat.
Email clients: Outlook, Thunderbird, Apple Mail.
Electron: VS Code, Slack desktop, Discord.

### Operating systems (30+)

Windows (ME through 11), macOS, iOS, Android, Chrome OS, HarmonyOS, Linux (Ubuntu, Debian, Fedora, Arch, Manjaro, Mint, SUSE, Red Hat, Gentoo, Slackware, Raspbian, Deepin, Elementary OS, and more), FreeBSD, OpenBSD, NetBSD, Solaris, AIX, Haiku, webOS, watchOS, Firefox OS, Tizen, KaiOS, Sailfish, Symbian, BlackBerry, QNX, Fuchsia, SerenityOS.

### Devices

**Smart TV (30+ brands):** Samsung/Tizen, LG/webOS, Hisense/VIDAA, Vizio/SmartCast, Philips/Saphi, TCL, Sharp/AQUOS, Panasonic/Viera, Toshiba/Regza, Skyworth, Haier, Vestel, Grundig, Changhong, Konka, Funai, Magnavox, Sanyo, Emerson, Thomson, Bang & Olufsen, Loewe, JVC, Hitachi, Insignia, Element, Polaroid, Arcelik/Beko, HiMedia, Apple TV, Chromecast, Fire TV, Nvidia Shield, Sony Bravia, Xiaomi Mi TV/Box, Roku.

**Consoles:** PlayStation (3/4/5/Vita/Portable), Xbox (One/Series X|S), Nintendo (Switch/Wii/3DS), Steam Deck, Ouya, Atari VCS, Steam Overlay.

**XR / VR / AR (15+):** Meta Quest (2/3/Pro), Apple Vision Pro, Microsoft HoloLens, HTC Vive (Focus/Flow/Cosmos/Pro/XR Elite), Valve Index, PlayStation VR (1/2), Google Glass, Pico, XREAL/Nreal (Air/Light/Beam), Samsung Gear VR, Pimax, HP Reverb, Varjo (Aero/XR-3/XR-4), Lynx R-1, Bigscreen Beyond.

**Phones & tablets (30+ vendors):** Apple (iPhone/iPad/iPod), Samsung (Galaxy S/A/Note/Tab/Fold/Flip), Google (Pixel/Nexus), Huawei, Xiaomi/Redmi/POCO, OnePlus, OPPO, Honor, Sony (Xperia), Amazon (Fire/Kindle), BlackBerry, ASUS (ZenFone/ROG), LG, Motorola/Moto, Lenovo (Tab/IdeaTab), Nokia, Sharp (AQUOS), HTC, ZTE, Infinix, Tecno, Realme, TCL, Coolpad, Meizu, Essential, and more.

**Vehicles (15+ brands):** Tesla, BMW, Mercedes-Benz/MBUX, Audi/MMI, Ford/SYNC, GM/Chevrolet, Hyundai, Kia, Volvo, Rivian, BYD, Jeep, Toyota, NIO, Polestar, Lucid, XPeng.

**Wearables:** Samsung Galaxy Watch, Google/ASUS/LG Pixel/Zen Watch, Apple Watch, Moto 360, OPPO Watch, Xiaomi Watch.

**IoT:** Amazon Echo/Echo Show/Echo Spot, Google Home/Nest Mini/Nest Hub/Nest Audio, Apple HomePod Mini, Facebook Portal, cameras (Nikon, Canon, GoPro, Sony Alpha).

**Portable media:** iPod, Zune.

### Rendering engines

Blink, Gecko, WebKit, Trident, EdgeHTML, Presto, Goanna, Servo, KHTML, NetFront, NetSurf, LibWeb/Ladybird, ArkWeb, Amaya, Lynx, W3M, Dillo, iCab, Tasman, Flow (Ekioh).

### CPU architectures

amd64, arm, arm64, ia32, ia64, mips, 68k, sparc, ppc, avr, irix, s390.

## Performance

- **LRU cache** — repeated UA strings skip parsing entirely
- **Keyword pre-filter** — regex rules have extracted literal hints; rules whose hints don't appear in the UA string are skipped
- **Lazy getters** — `browser`, `os`, `device`, `engine`, `cpu` are parsed on first access
- **Client Hints indexing** — composite cache key includes CH headers, so CH-enriched results are cached too

## Trust model

User-Agent and Client Hints headers are **client-controlled** — they can be spoofed. Do not use parse results for authentication, authorization, or security decisions. They are useful for analytics, feature detection, content negotiation, and UX adaptation.

## Why not

Deliberate omissions — these will **not** be added:

- Browser-side / edge-runtime support (server-only, `node:crypto` dependency)
- Regex-list hot-reload (compile-time inlining; update by bumping the package)
- `navigator.userAgentData` polyfill (that's a client concern)
- Probabilistic device detection via screen size / feature sniffing

## Links

- **Source:** [github.com/ExorTek/auth](https://github.com/ExorTek/auth)
- **Issues:** [github.com/ExorTek/auth/issues](https://github.com/ExorTek/auth/issues)
- **Changelog:** [CHANGELOG.md](https://github.com/ExorTek/auth/blob/master/packages/ua/CHANGELOG.md)

## License

MIT © ExorTek — see [LICENSE](./LICENSE).
