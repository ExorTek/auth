import {
  CH_UA,
  CH_UA_FULL_VERSION_LIST,
  CH_UA_ARCH,
  CH_UA_BITNESS,
  CH_UA_FORM_FACTORS,
  CH_UA_MOBILE,
  CH_UA_MODEL,
  CH_UA_PLATFORM,
  CH_UA_PLATFORM_VERSION,
  MOBILE,
  TABLET,
  SMARTTV,
  XR,
  EMBEDDED,
  WEARABLE,
} from './constants.js';
import { parseBrandList, parseHeaderValue } from './helpers.js';

/**
 * @typedef {Object} ClientHints
 * @property {Array<{brand: string, version: string}>} [brands]
 * @property {Array<{brand: string, version: string}>} [fullVersionList]
 * @property {boolean} [mobile]
 * @property {string} [model]
 * @property {string} [platform]
 * @property {string} [platformVersion]
 * @property {string} [architecture]
 * @property {string[]} [formFactors]
 * @property {string} [bitness]
 */

const browserHintsMap = Object.assign(Object.create(null), {
  'Google Chrome': 'Chrome',
  'Microsoft Edge': 'Edge',
  'Microsoft Edge WebView2': 'Edge WebView2',
  'Android WebView': 'Chrome WebView',
  HeadlessChrome: 'Chrome Headless',
  HuaweiBrowser: 'Huawei Browser',
  'Miui Browser': 'MIUI Browser',
  OperaMobile: 'Opera Mobile',
  YaBrowser: 'Yandex',
});

const formFactorsMap = Object.assign(Object.create(null), {
  Automotive: EMBEDDED,
  Mobile: MOBILE,
  Tablet: TABLET,
  EInk: TABLET,
  TV: SMARTTV,
  Watch: WEARABLE,
  VR: XR,
  XR: XR,
  Desktop: undefined,
  Unknown: undefined,
});

/**
 * @param {Record<string, string>} headers
 * @returns {ClientHints}
 */
export function parseClientHints(headers) {
  if (!headers) {
    return {};
  }

  const get = name => headers[name] ?? undefined;

  const mobileRaw = get(CH_UA_MOBILE);
  const ffRaw = get(CH_UA_FORM_FACTORS);

  return {
    brands: parseBrandList(get(CH_UA)),
    fullVersionList: parseBrandList(get(CH_UA_FULL_VERSION_LIST)),
    mobile: mobileRaw ? /\?1/.test(mobileRaw) : undefined,
    model: parseHeaderValue(get(CH_UA_MODEL)),
    platform: parseHeaderValue(get(CH_UA_PLATFORM)),
    platformVersion: parseHeaderValue(get(CH_UA_PLATFORM_VERSION)),
    architecture: parseHeaderValue(get(CH_UA_ARCH)),
    formFactors: ffRaw ? parseBrandList(ffRaw)?.map(b => b.brand || b) : undefined,
    bitness: parseHeaderValue(get(CH_UA_BITNESS)),
  };
}

/**
 * @param {ClientHints} ch
 * @param {Record<string, any>} browser
 * @returns {Record<string, any>}
 */
export function applyBrowserHints(ch, browser) {
  const brands = ch.fullVersionList || ch.brands;
  if (!brands) {
    return browser;
  }

  const result = { ...browser };
  let prevName;

  for (const { brand, version } of brands) {
    if (/not.a.brand/i.test(brand)) {
      continue;
    }

    const mapped = browserHintsMap[brand] || brand;

    if (
      !prevName ||
      (/Chrom/.test(prevName) && mapped !== 'Chromium') ||
      (prevName === 'Edge' && /WebView2/.test(mapped))
    ) {
      if (!(result.name && !/Chrom/.test(result.name) && /Chrom/.test(mapped))) {
        result.name = mapped;
        result.version = version;
        result.major = version?.split('.')[0];
      }
      prevName = mapped;
    }
  }

  return result;
}

/**
 * @param {ClientHints} ch
 * @param {Record<string, any>} device
 * @returns {Record<string, any>}
 */
export function applyDeviceHints(ch, device) {
  const result = { ...device };

  if (ch.mobile && !result.type) {
    result.type = MOBILE;
  }

  if (ch.model) {
    result.model = ch.model;
  }

  if (ch.formFactors) {
    for (const ff of ch.formFactors) {
      const mapped = formFactorsMap[ff];
      if (mapped !== undefined) {
        result.type = mapped;
        break;
      }
    }
  }

  return result;
}

/**
 * @param {ClientHints} ch
 * @param {Record<string, any>} os
 * @returns {Record<string, any>}
 */
export function applyOsHints(ch, os) {
  if (!ch.platform) {
    return os;
  }

  const result = { ...os };
  let version = ch.platformVersion;

  if (ch.platform === 'Windows' && version) {
    const major = parseInt(version.split('.')[0], 10);
    version = major >= 13 ? '11' : '10';
  }

  result.name = ch.platform;
  if (version) {
    result.version = version;
  }

  return result;
}

/**
 * @param {ClientHints} ch
 * @param {Record<string, any>} cpu
 * @returns {Record<string, any>}
 */
export function applyCpuHints(ch, cpu) {
  if (!ch.architecture) {
    return cpu;
  }

  let arch = ch.architecture;
  if (ch.bitness === '64') {
    arch += '64';
  }

  return { ...cpu, architecture: arch };
}

/**
 * @returns {string}
 */
export function buildAcceptCHValue() {
  return [
    CH_UA,
    CH_UA_FULL_VERSION_LIST,
    CH_UA_ARCH,
    CH_UA_BITNESS,
    CH_UA_FORM_FACTORS,
    CH_UA_MOBILE,
    CH_UA_MODEL,
    CH_UA_PLATFORM,
    CH_UA_PLATFORM_VERSION,
  ].join(', ');
}
