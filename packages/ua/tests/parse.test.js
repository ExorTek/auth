import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parse, parseBrowser, parseOS, parseDevice, parseEngine, parseCPU, ACCEPT_CH } from '../src/index.js';

// Common UA strings
const CHROME_WIN =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';
const FIREFOX_MAC = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0';
const SAFARI_IPHONE =
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1';
const EDGE_WIN =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0';
const ANDROID_CHROME =
  'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.71 Mobile Safari/537.36';
const SAMSUNG_INTERNET =
  'Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36';
const IPAD_SAFARI =
  'Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1';
const IE11 = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko';
const OPERA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/112.0.0.0';
const BRAVE =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Brave Chrome/126.0.0.0';

describe('parse()', () => {
  it('parses Chrome on Windows', () => {
    const r = parse(CHROME_WIN);
    assert.equal(r.browser.name, 'Chrome');
    assert.equal(r.browser.major, '126');
    assert.equal(r.os.name, 'Windows');
    assert.equal(r.engine.name, 'Blink');
    assert.equal(r.cpu.architecture, 'amd64');
  });

  it('parses Firefox on macOS', () => {
    const r = parse(FIREFOX_MAC);
    assert.equal(r.browser.name, 'Firefox');
    assert.equal(r.browser.major, '128');
    assert.equal(r.os.name, 'macOS');
    assert.equal(r.engine.name, 'Gecko');
  });

  it('parses Safari on iPhone', () => {
    const r = parse(SAFARI_IPHONE);
    assert.equal(r.browser.name, 'Mobile Safari');
    assert.equal(r.os.name, 'iOS');
    assert.equal(r.device.type, 'mobile');
    assert.equal(r.device.vendor, 'Apple');
  });

  it('parses Edge on Windows', () => {
    const r = parse(EDGE_WIN);
    assert.equal(r.browser.name, 'Edge');
    assert.equal(r.os.name, 'Windows');
  });

  it('parses Chrome on Android', () => {
    const r = parse(ANDROID_CHROME);
    assert.equal(r.browser.name, 'Mobile Chrome');
    assert.equal(r.os.name, 'Android');
    assert.equal(r.os.version, '14');
    assert.equal(r.device.type, 'mobile');
  });

  it('parses Samsung Internet', () => {
    const r = parse(SAMSUNG_INTERNET);
    assert.equal(r.browser.name, 'Samsung Internet');
    assert.equal(r.device.vendor, 'Samsung');
    assert.equal(r.device.type, 'mobile');
  });

  it('parses iPad Safari', () => {
    const r = parse(IPAD_SAFARI);
    assert.equal(r.browser.name, 'Mobile Safari');
    assert.equal(r.os.name, 'iOS');
    assert.equal(r.device.type, 'tablet');
    assert.equal(r.device.vendor, 'Apple');
  });

  it('parses IE 11', () => {
    const r = parse(IE11);
    assert.equal(r.browser.name, 'IE');
    assert.equal(r.browser.version, '11.0');
    assert.equal(r.engine.name, 'Trident');
  });

  it('parses Opera', () => {
    const r = parse(OPERA);
    assert.equal(r.browser.name, 'Opera');
  });

  it('parses Brave', () => {
    const r = parse(BRAVE);
    assert.equal(r.browser.name, 'Brave');
  });

  it('truncates UA at 500 chars', () => {
    const long = 'x'.repeat(1000);
    const r = parse(long);
    assert.equal(r.ua.length, 500);
  });

  it('handles empty / undefined UA', () => {
    assert.equal(parse('').ua, '');
    assert.equal(parse(undefined).ua, '');
    assert.equal(parse(null).ua, '');
  });

  it('returns structured result with all sections', () => {
    const r = parse(CHROME_WIN);
    assert.ok('browser' in r);
    assert.ok('os' in r);
    assert.ok('device' in r);
    assert.ok('engine' in r);
    assert.ok('cpu' in r);
    assert.ok('ua' in r);
  });
});

describe('parseBrowser()', () => {
  it('returns browser info only', () => {
    const b = parseBrowser(CHROME_WIN);
    assert.equal(b.name, 'Chrome');
    assert.equal(b.major, '126');
    assert.ok(!('os' in b));
  });
});

describe('parseOS()', () => {
  it('returns OS info only', () => {
    const o = parseOS(CHROME_WIN);
    assert.equal(o.name, 'Windows');
    assert.ok(!('browser' in o));
  });
});

describe('parseDevice()', () => {
  it('returns device info for mobile', () => {
    const d = parseDevice(SAFARI_IPHONE);
    assert.equal(d.type, 'mobile');
    assert.equal(d.vendor, 'Apple');
  });

  it('returns tablet for iPad', () => {
    const d = parseDevice(IPAD_SAFARI);
    assert.equal(d.type, 'tablet');
  });
});

describe('parseEngine()', () => {
  it('detects Blink for Chrome', () => {
    const e = parseEngine(CHROME_WIN);
    assert.equal(e.name, 'Blink');
  });

  it('detects Gecko for Firefox', () => {
    const e = parseEngine(FIREFOX_MAC);
    assert.equal(e.name, 'Gecko');
  });
});

describe('parseCPU()', () => {
  it('detects amd64', () => {
    const c = parseCPU(CHROME_WIN);
    assert.equal(c.architecture, 'amd64');
  });
});

describe('ACCEPT_CH', () => {
  it('contains all Client Hints headers', () => {
    assert.ok(ACCEPT_CH.includes('sec-ch-ua'));
    assert.ok(ACCEPT_CH.includes('sec-ch-ua-platform'));
    assert.ok(ACCEPT_CH.includes('sec-ch-ua-mobile'));
    assert.ok(ACCEPT_CH.includes('sec-ch-ua-model'));
  });
});

describe('Client Hints integration', () => {
  it('applies platform hint to override OS', () => {
    const r = parse(CHROME_WIN, {
      headers: {
        'sec-ch-ua-platform': '"macOS"',
        'sec-ch-ua-platform-version': '"14.5"',
      },
    });
    assert.equal(r.os.name, 'macOS');
    assert.equal(r.os.version, '14.5');
  });

  it('applies mobile hint to set device type', () => {
    const r = parse(CHROME_WIN, {
      headers: {
        'sec-ch-ua-mobile': '?1',
      },
    });
    assert.equal(r.device.type, 'mobile');
  });

  it('skips hints when clientHints: false', () => {
    const r = parse(CHROME_WIN, {
      clientHints: false,
      headers: {
        'sec-ch-ua-platform': '"macOS"',
      },
    });
    assert.equal(r.os.name, 'Windows');
  });
});

describe('Email clients', () => {
  it('detects Thunderbird', () => {
    const r = parseBrowser('Thunderbird/115.2.0');
    assert.equal(r.name, 'Thunderbird');
    assert.equal(r.version, '115.2.0');
    assert.equal(r.type, 'email');
  });

  it('detects Apple Mail', () => {
    const r = parseBrowser('mail/3654.60.5 cf');
    assert.equal(r.name, 'mail');
    assert.equal(r.type, 'email');
  });

  it('detects Outlook', () => {
    const r = parseBrowser('Microsoft Outlook/16.0.14326.20404');
    assert.equal(r.name, 'Microsoft Outlook');
    assert.equal(r.type, 'email');
  });

  it('detects Zimbra/Zdesktop', () => {
    const r = parseBrowser('Zimbra/8.8.15');
    assert.equal(r.name, 'Zimbra');
    assert.equal(r.type, 'email');
  });
});

describe('Media players', () => {
  it('detects VLC', () => {
    const r = parseBrowser('VLC/3.0.18 LibVLC/3.0.18');
    assert.equal(r.name, 'VLC');
    assert.equal(r.version, '3.0.18');
    assert.equal(r.type, 'mediaplayer');
  });

  it('detects iTunes', () => {
    const r = parseBrowser('iTunes/12.12.9');
    assert.equal(r.name, 'iTunes');
    assert.equal(r.type, 'mediaplayer');
  });

  it('detects Winamp', () => {
    const r = parseBrowser('Winamp 5.9.1');
    assert.equal(r.name, 'Winamp');
    assert.equal(r.type, 'mediaplayer');
  });

  it('detects foobar2000', () => {
    const r = parseBrowser('foobar2000/2.0');
    assert.equal(r.name, 'foobar2000');
    assert.equal(r.type, 'mediaplayer');
  });
});

describe('Extra devices', () => {
  it('detects Nook tablet', () => {
    const r = parseDevice('Nook Color build/NookColor');
    assert.equal(r.vendor, 'Nook');
    assert.equal(r.type, 'tablet');
  });

  it('detects Essential PH-1', () => {
    const r = parseDevice('PH-1 Build/OPM1');
    assert.equal(r.vendor, 'Essential');
    assert.equal(r.model, 'PH-1');
    assert.equal(r.type, 'mobile');
  });
});

describe('Vehicles', () => {
  it('detects Rivian R1T', () => {
    const r = parseDevice('Rivian R1T Browser/1.0');
    assert.equal(r.vendor, 'Rivian');
    assert.equal(r.model, 'R1T');
  });

  it('detects Tesla', () => {
    const r = parseDevice(
      'Mozilla/5.0 (X11; Linux) AppleWebKit/534.34 (KHTML, like Gecko) QtCarBrowser Safari/534.34 Tesla/2022.4',
    );
    assert.equal(r.vendor, 'Tesla');
    assert.equal(r.type, 'vehicle');
  });
});

describe('TV devices', () => {
  it('detects Samsung Tizen TV', () => {
    const r = parseDevice(
      'Mozilla/5.0 (SMART-TV; LINUX; Tizen 6.5) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/5.0 Chrome/85.0.4183.93 TV Safari/537.36',
    );
    assert.equal(r.vendor, 'Samsung');
    assert.equal(r.type, 'smarttv');
  });

  it('detects LG webOS TV', () => {
    const r = parseDevice(
      'Mozilla/5.0 (Web0S; Linux/SmartTV) AppleWebKit/537.36 Chrome/79.0.3945.79 Safari/537.36 WebAppManager',
    );
    assert.equal(r.type, 'smarttv');
  });

  it('detects Roku', () => {
    const r = parseDevice('Roku4640X/DVP-7.70 (297.70E04154A)');
    assert.equal(r.vendor, 'Roku');
    assert.equal(r.type, 'smarttv');
  });
});

describe('Console devices', () => {
  it('detects PlayStation 5', () => {
    const r = parseDevice('Mozilla/5.0 (PlayStation 5) AppleWebKit/537.36');
    assert.equal(r.vendor, 'Sony');
    assert.equal(r.model, 'PlayStation 5');
    assert.equal(r.type, 'console');
  });

  it('detects Xbox', () => {
    const r = parseDevice('Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox Series X) AppleWebKit/537.36');
    assert.equal(r.vendor, 'Microsoft');
    assert.equal(r.type, 'console');
  });

  it('detects Steam Deck', () => {
    const r = parseDevice('Mozilla/5.0 (Linux; U; Valve Steam Deck) AppleWebKit/537.36');
    assert.equal(r.vendor, 'Valve');
    assert.equal(r.model, 'Steam Deck');
    assert.equal(r.type, 'console');
  });
});

describe('XR devices', () => {
  it('detects Meta Quest', () => {
    const r = parseDevice('Mozilla/5.0 (Linux; Android 12; Quest 3) AppleWebKit/537.36 VR Safari/537.36');
    assert.equal(r.vendor, 'Facebook');
    assert.equal(r.type, 'xr');
  });

  it('detects Apple Vision Pro', () => {
    const r = parseDevice('Mozilla/5.0 (Apple Vision Pro) AppleWebKit/605.1.15');
    assert.equal(r.vendor, 'Apple');
    assert.equal(r.model, 'Vision Pro');
    assert.equal(r.type, 'xr');
  });
});

describe('In-app (Electron/desktop)', () => {
  it('detects VS Code', () => {
    const r = parseBrowser(
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Code/1.82.0 Chrome/116.0.5845.190 Electron/26.1.0 Safari/537.36',
    );
    assert.equal(r.name, 'VS Code');
    assert.equal(r.type, 'inapp');
  });

  it('detects TikTok Lite', () => {
    const r = parseBrowser('UltraLite app_version/2.3.1');
    assert.equal(r.name, 'TikTok Lite');
    assert.equal(r.type, 'inapp');
  });
});
