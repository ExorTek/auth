// Tiny, opinionated UA → friendly label mapper. Not a UA parsing lib —
// no dependencies, no attempt at exhaustive coverage. We match the top
// ~20 patterns and fall through to a stock "browser · os" label for
// everything else. `settings/sessions` UIs get "iPhone 14 · Chrome"
// instead of the 300-character raw UA string.

const OS_PATTERNS = [
  [/iPhone OS ([\d_]+)/, ua => `iPhone (iOS ${ua[1].replace(/_/g, '.')})`],
  [/iPad; .*OS ([\d_]+)/, ua => `iPad (iOS ${ua[1].replace(/_/g, '.')})`],
  [/Mac OS X ([\d_]+)/, ua => `Mac (macOS ${ua[1].replace(/_/g, '.')})`],
  [/Android (\d+)/, ua => `Android ${ua[1]}`],
  [/Windows NT 10\.0/, () => 'Windows 10/11'],
  [/Windows NT 6\.3/, () => 'Windows 8.1'],
  [/Windows NT 6\.2/, () => 'Windows 8'],
  [/Windows NT 6\.1/, () => 'Windows 7'],
  [/Linux/, () => 'Linux'],
  [/CrOS/, () => 'ChromeOS'],
];

const BROWSER_PATTERNS = [
  [/Edg\/[\d.]+/, () => 'Edge'],
  [/OPR\/[\d.]+/, () => 'Opera'],
  [/Chrome\/[\d.]+/, () => 'Chrome'],
  [/Firefox\/[\d.]+/, () => 'Firefox'],
  [/Safari\/[\d.]+/, () => 'Safari'],
  [/curl\/[\d.]+/, () => 'curl'],
  [/HTTPie\/[\d.]+/, () => 'HTTPie'],
  [/PostmanRuntime\/[\d.]+/, () => 'Postman'],
];

/**
 * Convert a User-Agent string into a short, human-readable label. Meant
 * for a settings/sessions list — deliberately lossy so users see
 * "iPhone (iOS 17.4) · Safari" instead of parsing 300 characters of UA.
 *
 * @param {string | undefined | null} ua
 * @returns {string}                          Empty string when input is not a usable UA.
 */
export function deriveDeviceLabel(ua) {
  if (typeof ua !== 'string' || ua.length === 0) {
    return '';
  }
  const os = matchFirst(ua, OS_PATTERNS);
  const browser = matchFirst(ua, BROWSER_PATTERNS);
  if (os && browser) {
    return `${os} · ${browser}`;
  }
  if (os) {
    return os;
  }
  if (browser) {
    return browser;
  }
  // Fall through: return a short slug of the UA so at least *something*
  // shows up on the settings page.
  return ua.length > 40 ? `${ua.slice(0, 37)}...` : ua;
}

function matchFirst(input, patterns) {
  for (const [re, fmt] of patterns) {
    const m = input.match(re);
    if (m) {
      return fmt(m);
    }
  }
  return null;
}
