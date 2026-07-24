# `@exortek/ua`

High-performance User-Agent parser with browser, OS, device, engine, and CPU detection — plus bot/AI crawler taxonomy, Client Hints support, and request fingerprinting.

## Install

```bash
npm install @exortek/ua
```

Node.js **22 or newer**.

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

```js
import { detectBot, isAICrawler } from '@exortek/ua/bots';

const bot = detectBot('GPTBot/1.2');
console.log(bot.category);    // 'ai-training'
console.log(bot.confidence);  // 'medium'

isAICrawler('GPTBot/1.2');    // true
```

## Entry points

| Import path | What it exports |
|---|---|
| `@exortek/ua` | `parse`, `parseBrowser`, `parseOS`, `parseDevice`, `parseEngine`, `parseCPU`, `satisfies`, `isFrozenUA`, `clearCache`, `ACCEPT_CH`, `VARY_CH`, `BOT_CATEGORY` |
| `@exortek/ua/bots` | `detectBot`, `isBot`, `isAICrawler`, `isAIAssistant`, `isSearchBot`, `isSocialPreview`, `isSEOBot`, `isSecurityScanner`, `isAutomation`, `createBotDetector`, `clearBotCache`, `BOT_CATEGORY` |
| `@exortek/ua/fingerprint` | `createFingerprint`, `fingerprintRequest` |
| `@exortek/ua/middleware/express` | `uaMiddleware` |
| `@exortek/ua/middleware/fastify` | `uaPlugin` |
| `@exortek/ua/middleware/bot-guard` | `botGuard` (Express) |
| `@exortek/ua/middleware/bot-guard/fastify` | `botGuardPlugin` |

## API

### `parse(ua, options?)`

Parse a User-Agent string. Returns `{ ua, browser, os, device, engine, cpu }` with lazy getters — sections are only parsed when accessed.

```js
const result = parse(ua, {
  headers: req.headers,   // pass request headers for Client Hints
  clientHints: true,      // default: true
});
```

**`browser`** — `{ name, version, major, type }`
**`os`** — `{ name, version }`
**`device`** — `{ type, vendor, model }`
**`engine`** — `{ name, version }`
**`cpu`** — `{ architecture }`

### `parseBrowser(ua)`, `parseOS(ua)`, `parseDevice(ua)`, `parseEngine(ua)`, `parseCPU(ua)`

Parse only one section. Faster when you need a single field.

### `satisfies(result, conditions)`

Check if a parse result matches version conditions:

```js
satisfies(result, { chrome: '>=120', firefox: '>=115' });        // OR
satisfies(result, { mobile: { safari: '>=16' } });               // device-scoped
satisfies(result, { desktop: { chrome: '>=120' } });
```

Operators: `>=`, `>`, `<=`, `<`, `=`, `==`, `!=`

### `isFrozenUA(ua)`

Returns `true` if the UA string uses Chrome 107+ frozen/reduced format. When true, Client Hints headers are required for accurate version and device info.

### `detectBot(ua)`

Returns `{ name, version, type, category, confidence }` or `null`.

**`confidence`**: `'high'` (named + versioned + categorized), `'medium'` (one of those), `'low'` (generic).

### `isBot`, `isAICrawler`, `isSearchBot`, `isSecurityScanner`, `isAutomation`, `isSocialPreview`, `isSEOBot`, `isAIAssistant`

Boolean shorthand functions — each calls `detectBot` internally.

### `createBotDetector(extraPatterns)`

Create a detector with custom patterns that fall through to built-in detection:

```js
const detect = createBotDetector([
  { pattern: /mybot\/([\d.]+)/i, name: 'MyBot', category: 'internal' },
]);
```

### `createFingerprint(input, options?)`

Deterministic hash from request signals:

```js
const fp = createFingerprint({
  ua: req.headers['user-agent'],
  headers: req.headers,
  ip: req.ip,
}, { subnet: true });
// → 'fp_a8f3b2c1...'
```

**Options**: `includeIP` (full IP), `subnet` (IPv4 /24, IPv6 /64), `strict` (default `true`, includes semi-stable signals), `algorithm` (default `'sha256'`).

### `fingerprintRequest(req, options?)`

Shorthand — extracts `ua`, `headers`, `ip` from a request object.

### Express middleware

```js
import { uaMiddleware } from '@exortek/ua/middleware/express';

app.get('/api', uaMiddleware(), (req, res) => {
  console.log(req.ua.browser.name);
  console.log(req.ua.bot);
});
```

**Options**:

| Option | Default | Description |
|---|---|---|
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

```js
import { uaPlugin } from '@exortek/ua/middleware/fastify';

await app.register(uaPlugin, { detectBots: true });

app.get('/', async (request) => {
  console.log(request.ua.browser.name);
});
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
|---|---|---|
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
|---|---|
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

## License

MIT
