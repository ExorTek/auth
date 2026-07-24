import { applyRulesFiltered, buildHintIndex } from './internal/engine.js';
import { sanitizeUA, lower } from './internal/helpers.js';
import { BOT_CATEGORY } from './internal/constants.js';
import { crawlerRules, fetcherRules, cliRules, libraryRules, botTaxonomy } from './internal/regexes/bots.js';
import { botCache } from './internal/cache.js';

const allBotRules = [...crawlerRules, ...fetcherRules, ...cliRules, ...libraryRules];
const botHints = buildHintIndex(allBotRules);

/**
 * @typedef {'high'|'medium'|'low'} BotConfidence
 */

/**
 * @typedef {Object} BotInfo
 * @property {string} name
 * @property {string} [version]
 * @property {string} type
 * @property {string} category
 * @property {BotConfidence} confidence
 */

/**
 * Detect whether a UA string belongs to a bot / crawler / fetcher.
 *
 *   import { detectBot } from '@exortek/ua/bots';
 *
 *   const bot = detectBot(req.headers['user-agent']);
 *   if (bot) {
 *     console.log(bot.name);      // 'Googlebot'
 *     console.log(bot.type);      // 'crawler'
 *     console.log(bot.category);  // 'search'
 *   }
 *
 * @param {string} ua
 * @returns {BotInfo|null}
 */
export function detectBot(ua) {
  const safe = sanitizeUA(ua);
  const cached = botCache.get(safe);
  if (cached !== undefined) {
    return cached;
  }

  const uaLower = lower(safe);
  const result = applyRulesFiltered(safe, uaLower, allBotRules, botHints);

  if (!result.type) {
    botCache.set(safe, null);
    return null;
  }

  const name = result.name || 'unknown';
  const nameLower = lower(name);
  const category = botTaxonomy[nameLower] || BOT_CATEGORY.GENERIC;
  const hasVersion = !!result.version;
  const isGeneric = category === BOT_CATEGORY.GENERIC;
  const confidence = hasVersion && !isGeneric ? 'high' : hasVersion || !isGeneric ? 'medium' : 'low';

  const info = {
    name,
    version: result.version || undefined,
    type: result.type,
    category,
    confidence,
  };

  botCache.set(safe, info);
  return info;
}

/**
 * Quick boolean check: is this UA a bot?
 *
 * @param {string} ua
 * @returns {boolean}
 */
export function isBot(ua) {
  return detectBot(ua) !== null;
}

/**
 * Is this UA an AI training crawler?
 *
 * @param {string} ua
 * @returns {boolean}
 */
export function isAICrawler(ua) {
  const bot = detectBot(ua);
  return bot !== null && bot.category === BOT_CATEGORY.AI_TRAINING;
}

/**
 * Is this UA an AI assistant fetcher?
 *
 * @param {string} ua
 * @returns {boolean}
 */
export function isAIAssistant(ua) {
  const bot = detectBot(ua);
  return bot !== null && bot.category === BOT_CATEGORY.AI_ASSISTANT;
}

/**
 * Is this UA a search engine crawler?
 *
 * @param {string} ua
 * @returns {boolean}
 */
export function isSearchBot(ua) {
  const bot = detectBot(ua);
  return bot !== null && bot.category === BOT_CATEGORY.SEARCH;
}

/**
 * Is this UA a social media preview fetcher?
 *
 * @param {string} ua
 * @returns {boolean}
 */
export function isSocialPreview(ua) {
  const bot = detectBot(ua);
  return bot !== null && bot.category === BOT_CATEGORY.SOCIAL_PREVIEW;
}

/**
 * Is this UA an SEO tool crawler?
 *
 * @param {string} ua
 * @returns {boolean}
 */
export function isSEOBot(ua) {
  const bot = detectBot(ua);
  return bot !== null && bot.category === BOT_CATEGORY.SEO;
}

/**
 * Is this UA a security scanner?
 *
 * @param {string} ua
 * @returns {boolean}
 */
export function isSecurityScanner(ua) {
  const bot = detectBot(ua);
  return bot !== null && bot.category === BOT_CATEGORY.SECURITY_SCANNER;
}

/**
 * Is this UA an automation tool? (headless browsers, test frameworks)
 *
 * @param {string} ua
 * @returns {boolean}
 */
export function isAutomation(ua) {
  const bot = detectBot(ua);
  return bot !== null && bot.category === BOT_CATEGORY.AUTOMATION;
}

/**
 * Create a custom bot detector with additional patterns.
 *
 *   import { createBotDetector } from '@exortek/ua/bots';
 *
 *   const detect = createBotDetector([
 *     { pattern: /mycompanybot/i, name: 'MyBot', category: 'internal' },
 *   ]);
 *   detect('MyCompanyBot/1.0'); // { name: 'MyBot', ... }
 *
 * @param {Array<{pattern: RegExp, name: string, category?: string}>} extraPatterns
 * @returns {(ua: string) => BotInfo|null}
 */
export function createBotDetector(extraPatterns) {
  return function detect(ua) {
    const safe = sanitizeUA(ua);
    for (const { pattern, name, category } of extraPatterns) {
      const m = pattern.exec(safe);
      if (m) {
        const cat = category || BOT_CATEGORY.GENERIC;
        const ver = m[1] || undefined;
        return {
          name,
          version: ver,
          type: 'crawler',
          category: cat,
          confidence:
            ver && cat !== BOT_CATEGORY.GENERIC ? 'high' : ver || cat !== BOT_CATEGORY.GENERIC ? 'medium' : 'low',
        };
      }
    }
    return detectBot(ua);
  };
}

/**
 * Clear the bot detection cache.
 */
export function clearBotCache() {
  botCache.clear();
}

export { BOT_CATEGORY };
