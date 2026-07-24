import {
  detectBot,
  isBot,
  isAICrawler,
  isAIAssistant,
  isSearchBot,
  isSEOBot,
  isSecurityScanner,
  isAutomation,
  isSocialPreview,
  createBotDetector,
  BOT_CATEGORY,
} from '@exortek/ua/bots';

// Full bot detection
const bot = detectBot('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');
if (bot) {
  console.log(bot.name); // 'Googlebot'
  console.log(bot.version); // '2.1'
  console.log(bot.type); // 'crawler'
  console.log(bot.category); // 'search'
  console.log(bot.confidence); // 'high'
}

// Quick boolean checks
console.log(isBot('Googlebot/2.1')); // true
console.log(isSearchBot('Googlebot/2.1')); // true
console.log(isAICrawler('GPTBot/1.2')); // true
console.log(isAIAssistant('ChatGPT-User')); // true
console.log(isSEOBot('AhrefsBot/7.0')); // true
console.log(isSecurityScanner('Nessus SOAP')); // true
console.log(isAutomation('HeadlessChrome/126.0')); // true
console.log(isSocialPreview('Twitterbot/1.0')); // true

// Confidence levels
const high = detectBot('Googlebot/2.1'); // named + versioned + categorized
console.log(high?.confidence); // 'high'

const medium = detectBot('GPTBot'); // categorized but no version
console.log(medium?.confidence); // 'medium'

const low = detectBot('bot'); // generic, no version
console.log(low?.confidence); // 'low'

// Custom bot detector — add your own internal bots
const detect = createBotDetector([
  { pattern: /internalbot\/([\d.]+)/i, name: 'InternalBot', category: 'internal' },
  { pattern: /health-?check/i, name: 'HealthCheck', category: BOT_CATEGORY.MONITORING },
]);

console.log(detect('InternalBot/3.1')); // { name: 'InternalBot', version: '3.1', ... }
console.log(detect('health-check')); // { name: 'HealthCheck', ... }
console.log(detect('Googlebot/2.1')); // falls through to built-in detection

// Bot blocking middleware pattern
function blockBots(req, res, next) {
  const ua = req.headers['user-agent'] || '';
  if (isAICrawler(ua)) {
    res.status(403).send('AI crawling not permitted');
    return;
  }
  next();
}
