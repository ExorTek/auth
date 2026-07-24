import { parse, parseBrowser, parseOS, parseDevice, parseEngine, parseCPU, satisfies, isFrozenUA } from '@exortek/ua';

// Full parse
const result = parse(
  'Mozilla/5.0 (Linux; Android 14; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.71 Mobile Safari/537.36',
);

console.log(result.browser); // { name: 'Chrome', version: '126.0.6478.71', major: '126' }
console.log(result.os); // { name: 'Android', version: '14' }
console.log(result.device); // { type: 'mobile', vendor: 'Samsung', model: 'SM-S911B' }
console.log(result.engine); // { name: 'Blink', version: '126.0.6478.71' }
console.log(result.cpu); // { architecture: 'amd64' } (from Chrome's UA)

// Individual parsers (skip sections you don't need)
const browser = parseBrowser('Mozilla/5.0 ... Chrome/126.0.0.0 Safari/537.36');
console.log(browser.name, browser.major); // 'Chrome' '126'

const os = parseOS('Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...');
console.log(os.name, os.version); // 'Windows' '10'

const device = parseDevice('Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) ...');
console.log(device.type, device.vendor); // 'tablet' 'Apple'

// Version matching
const r = parse(
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
);

console.log(satisfies(r, { chrome: '>=120' })); // true
console.log(satisfies(r, { chrome: '<100' })); // false
console.log(satisfies(r, { firefox: '>=115', chrome: '>=120' })); // true (OR logic)

// Device-scoped version matching
console.log(satisfies(r, { mobile: { safari: '>=16' } })); // false (desktop Chrome)
console.log(satisfies(r, { desktop: { chrome: '>=120' } })); // true

// Frozen UA detection
const frozenUA =
  'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36';

if (isFrozenUA(frozenUA)) {
  console.log('Frozen UA detected — use Client Hints for accurate version/device info');
}

// Parse engine

const engine = parseEngine(
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
);
console.log(engine.name, engine.version); // 'Blink' '126.0.0.0'
const cpu = parseCPU(
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
);
console.log(cpu.architecture); // 'amd64'
