import { parse, isFrozenUA, ACCEPT_CH, VARY_CH } from '@exortek/ua';

// Step 1: Send Accept-CH header so browsers provide high-entropy hints
// (The middleware adapters do this automatically)
function setAcceptCH(res) {
  res.setHeader('Accept-CH', ACCEPT_CH);
  res.setHeader('Vary', VARY_CH);
}

// Step 2: Parse with Client Hints on subsequent requests
function handleRequest(req) {
  const ua = req.headers['user-agent'];

  // Detect frozen UA — hints are required for accurate results
  if (isFrozenUA(ua)) {
    console.log('Chrome 107+ frozen UA — reading Client Hints');
  }

  const result = parse(ua, {
    headers: req.headers, // Pass all headers, CH headers are extracted automatically
    clientHints: true, // Default, can be disabled with false
  });

  // Client Hints enrich these results with accurate data
  console.log(result.browser.name); // 'Chrome'
  console.log(result.browser.version); // '126.0.6478.71' (full version from hints)
  console.log(result.device.model); // 'SM-S911B' (from Sec-CH-UA-Model)
  console.log(result.os.name); // 'Android'
  console.log(result.os.version); // '14.0.0' (from Sec-CH-UA-Platform-Version)
  console.log(result.cpu.architecture); // 'arm' (from Sec-CH-UA-Arch)
}

// Client Hints headers the parser reads:
// - Sec-CH-UA                  → browser brand list
// - Sec-CH-UA-Full-Version-List → full version per brand
// - Sec-CH-UA-Mobile           → mobile boolean
// - Sec-CH-UA-Model            → device model
// - Sec-CH-UA-Platform         → OS name
// - Sec-CH-UA-Platform-Version → OS version
// - Sec-CH-UA-Arch             → CPU architecture
// - Sec-CH-UA-Bitness          → 32/64 bit
// - Sec-CH-UA-Form-Factors     → device form factors
