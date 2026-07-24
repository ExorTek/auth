import { isString, isObject } from '@exortek/shared/predicates';
import { applyRulesFiltered, buildHintIndex } from './internal/engine.js';
import { sanitizeUA, majorize } from './internal/helpers.js';
import { browserRules } from './internal/regexes/browser.js';
import { osRules } from './internal/regexes/os.js';
import { deviceRules } from './internal/regexes/device.js';
import { engineRules } from './internal/regexes/engine.js';
import { cpuRules } from './internal/regexes/cpu.js';
import {
  parseClientHints,
  applyBrowserHints,
  applyDeviceHints,
  applyOsHints,
  applyCpuHints,
  buildAcceptCHValue,
} from './internal/client-hints.js';
import {
  UA_MAX_LENGTH,
  CH_UA,
  CH_UA_FULL_VERSION_LIST,
  CH_UA_MOBILE,
  CH_UA_MODEL,
  CH_UA_PLATFORM,
  CH_UA_PLATFORM_VERSION,
  CH_UA_ARCH,
  CH_UA_BITNESS,
  CH_UA_FORM_FACTORS,
} from './internal/constants.js';
import { parseCache } from './internal/cache.js';

const CH_KEYS = [
  CH_UA,
  CH_UA_FULL_VERSION_LIST,
  CH_UA_MOBILE,
  CH_UA_MODEL,
  CH_UA_PLATFORM,
  CH_UA_PLATFORM_VERSION,
  CH_UA_ARCH,
  CH_UA_BITNESS,
  CH_UA_FORM_FACTORS,
];

function buildCacheKey(ua, headers) {
  let key = ua;
  for (const k of CH_KEYS) {
    const v = headers[k] ?? headers[k.toLowerCase()];
    if (v) {
      key += '\0' + (v.length > UA_MAX_LENGTH ? v.substring(0, UA_MAX_LENGTH) : v);
    }
  }
  return key;
}

// Pre-build hint indices at module load (one-time cost)
const browserHints = buildHintIndex(browserRules);
const osHints = buildHintIndex(osRules);
const deviceHints = buildHintIndex(deviceRules);
const engineHints = buildHintIndex(engineRules);
const cpuHints = buildHintIndex(cpuRules);

/**
 * @typedef {Object} BrowserResult
 * @property {string} [name]
 * @property {string} [version]
 * @property {string} [major]
 * @property {string} [type]
 */

/**
 * @typedef {Object} OSResult
 * @property {string} [name]
 * @property {string} [version]
 */

/**
 * @typedef {Object} DeviceResult
 * @property {string} [type]
 * @property {string} [vendor]
 * @property {string} [model]
 */

/**
 * @typedef {Object} EngineResult
 * @property {string} [name]
 * @property {string} [version]
 */

/**
 * @typedef {Object} CPUResult
 * @property {string} [architecture]
 */

/**
 * @typedef {Object} UAResult
 * @property {string} ua
 * @property {BrowserResult} browser
 * @property {OSResult} os
 * @property {DeviceResult} device
 * @property {EngineResult} engine
 * @property {CPUResult} cpu
 */

/**
 * @typedef {Object} ParseOptions
 * @property {Record<string, string>} [headers]
 * @property {boolean} [clientHints=true]
 */

function runBrowser(safe, lower) {
  const raw = applyRulesFiltered(safe, lower, browserRules, browserHints);
  if (raw.version) {
    raw.major = majorize(raw.version);
  }
  return {
    name: raw.name,
    version: raw.version,
    major: raw.major,
    type: raw.type,
  };
}

function runOS(safe, lower) {
  const raw = applyRulesFiltered(safe, lower, osRules, osHints);
  return { name: raw.name, version: raw.version };
}

function runDevice(safe, lower) {
  const raw = applyRulesFiltered(safe, lower, deviceRules, deviceHints);
  return { type: raw.type, vendor: raw.vendor, model: raw.model };
}

function runEngine(safe, lower) {
  const raw = applyRulesFiltered(safe, lower, engineRules, engineHints);
  return { name: raw.name, version: raw.version };
}

function runCPU(safe, lower) {
  const raw = applyRulesFiltered(safe, lower, cpuRules, cpuHints);
  return { architecture: raw.architecture };
}

/**
 * Parse a User-Agent string and optional Client Hints headers.
 * Results are cached (LRU) and lazily computed per section.
 *
 *   import { parse } from '@exortek/ua';
 *
 *   const result = parse('Mozilla/5.0 ...');
 *   console.log(result.browser.name);  // 'Chrome'
 *   console.log(result.os.name);       // 'Windows'
 *   console.log(result.device.type);   // 'mobile'
 *
 *   // With Client Hints (server-side)
 *   const result2 = parse(req.headers['user-agent'], {
 *     headers: req.headers,
 *   });
 *
 * @param {string} ua
 * @param {ParseOptions} [options]
 * @returns {UAResult}
 */
export function parse(ua, options) {
  const safe = sanitizeUA(ua);
  const useHints = options?.clientHints !== false;
  const hasHints = useHints && options?.headers;
  const cacheKey = hasHints ? buildCacheKey(safe, options.headers) : safe;

  const cached = parseCache.get(cacheKey);
  if (cached) {
    return cached;
  }

  const lower = safe.toLowerCase();
  let _browser, _os, _device, _engine, _cpu;

  const result = {
    ua: safe,
    get browser() {
      if (!_browser) {
        _browser = runBrowser(safe, lower);
      }
      return _browser;
    },
    get os() {
      if (!_os) {
        _os = runOS(safe, lower);
      }
      return _os;
    },
    get device() {
      if (!_device) {
        _device = runDevice(safe, lower);
      }
      return _device;
    },
    get engine() {
      if (!_engine) {
        _engine = runEngine(safe, lower);
      }
      return _engine;
    },
    get cpu() {
      if (!_cpu) {
        _cpu = runCPU(safe, lower);
      }
      return _cpu;
    },
  };

  if (hasHints) {
    const ch = parseClientHints(options.headers);
    _browser = applyBrowserHints(ch, runBrowser(safe, lower));
    _device = applyDeviceHints(ch, runDevice(safe, lower));
    _os = applyOsHints(ch, runOS(safe, lower));
    _cpu = applyCpuHints(ch, runCPU(safe, lower));
  }

  parseCache.set(cacheKey, result);
  return result;
}

/**
 * Parse only the browser portion.
 *
 * @param {string} ua
 * @returns {BrowserResult}
 */
export function parseBrowser(ua) {
  const safe = sanitizeUA(ua);
  return runBrowser(safe, safe.toLowerCase());
}

/**
 * Parse only the OS portion.
 *
 * @param {string} ua
 * @returns {OSResult}
 */
export function parseOS(ua) {
  const safe = sanitizeUA(ua);
  return runOS(safe, safe.toLowerCase());
}

/**
 * Parse only the device portion.
 *
 * @param {string} ua
 * @returns {DeviceResult}
 */
export function parseDevice(ua) {
  const safe = sanitizeUA(ua);
  return runDevice(safe, safe.toLowerCase());
}

/**
 * Parse only the engine portion.
 *
 * @param {string} ua
 * @returns {EngineResult}
 */
export function parseEngine(ua) {
  const safe = sanitizeUA(ua);
  return runEngine(safe, safe.toLowerCase());
}

/**
 * Parse only the CPU portion.
 *
 * @param {string} ua
 * @returns {CPUResult}
 */
export function parseCPU(ua) {
  const safe = sanitizeUA(ua);
  return runCPU(safe, safe.toLowerCase());
}

/**
 * Detect whether a UA string uses Chrome's frozen/reduced format.
 * Chrome 107+ sends a reduced UA where the version is locked and
 * platform info is generalized. When true, Client Hints are required
 * for accurate browser version and OS detection.
 *
 *   if (isFrozenUA(ua)) {
 *     // Must use Client Hints for accurate version/OS
 *   }
 *
 * @param {string} ua
 * @returns {boolean}
 */
export function isFrozenUA(ua) {
  if (!isString(ua)) {
    return false;
  }
  return (
    /Chrome\/\d+\.0\.0\.0 /.test(ua) &&
    /\((?:Linux; Android 10; K|Windows NT 10\.0; Win64; x64|Macintosh; Intel Mac OS X 10_15_7|X11; Linux x86_64|X11; CrOS x86_64 14541\.0\.0|Fuchsia)\)/.test(
      ua,
    )
  );
}

/**
 * Compare a parse result against version conditions.
 *
 *   import { parse, satisfies } from '@exortek/ua';
 *
 *   const r = parse(ua);
 *   satisfies(r, { chrome: '>=120', firefox: '>=115' });
 *   satisfies(r, { mobile: { safari: '>=16' } });
 *
 * @param {UAResult} result
 * @param {Record<string, string|Record<string, string>>} conditions
 * @returns {boolean}
 */
export function satisfies(result, conditions) {
  const browser = result.browser;
  if (!browser?.name) {
    return false;
  }
  const bName = browser.name.toLowerCase();
  const bMajor = parseInt(browser.major, 10);
  if (isNaN(bMajor)) {
    return false;
  }

  for (const [key, val] of Object.entries(conditions)) {
    if (isObject(val)) {
      const deviceType = key.toLowerCase();
      const currentType = result.device?.type;
      if (currentType !== deviceType && !(deviceType === 'desktop' && !currentType)) {
        continue;
      }
      for (const [bKey, bVal] of Object.entries(val)) {
        if (matchBrowserName(bName, bKey) && evalCondition(bMajor, bVal)) {
          return true;
        }
      }
    } else {
      if (matchBrowserName(bName, key) && evalCondition(bMajor, val)) {
        return true;
      }
    }
  }
  return false;
}

function matchBrowserName(actual, target) {
  const t = target.toLowerCase();
  if (actual === t) {
    return true;
  }
  const aliases = {
    chrome: ['chrome', 'mobile chrome', 'chrome webview', 'chrome headless'],
    firefox: ['firefox', 'mobile firefox', 'firefox focus'],
    safari: ['safari', 'mobile safari'],
    edge: ['edge'],
    opera: ['opera', 'opera mini', 'opera mobile'],
    samsung: ['samsung internet'],
    ie: ['ie'],
  };
  return aliases[t]?.includes(actual) || false;
}

function evalCondition(major, condition) {
  const m = condition.match(/^([><=!]+)\s*(\d+)$/);
  if (!m) {
    return false;
  }
  const [, op, numStr] = m;
  const num = parseInt(numStr, 10);
  switch (op) {
    case '>=':
      return major >= num;
    case '>':
      return major > num;
    case '<=':
      return major <= num;
    case '<':
      return major < num;
    case '=':
    case '==':
      return major === num;
    case '!=':
      return major !== num;
    default:
      return false;
  }
}

/**
 * Clear the internal parse cache.
 */
export function clearCache() {
  parseCache.clear();
}

/**
 * The `Accept-CH` header value to send so browsers provide
 * high-entropy Client Hints. Set this on every response:
 *
 *   res.setHeader('Accept-CH', ACCEPT_CH);
 *
 * The middleware adapters do this automatically.
 *
 * @type {string}
 */
export const ACCEPT_CH = buildAcceptCHValue();

/**
 * The `Vary` header value to add when the response depends on
 * Client Hints. Required for correct CDN/proxy caching:
 *
 *   res.setHeader('Vary', VARY_CH);
 *
 * @type {string}
 */
export const VARY_CH = ACCEPT_CH;

export { BOT_CATEGORY } from './internal/constants.js';
