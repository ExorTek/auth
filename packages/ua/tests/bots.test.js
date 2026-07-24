import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  detectBot,
  isBot,
  isAICrawler,
  isAIAssistant,
  isSearchBot,
  isSocialPreview,
  isSEOBot,
  BOT_CATEGORY,
} from '../src/bots.js';

describe('detectBot()', () => {
  it('detects Googlebot', () => {
    const bot = detectBot('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');
    assert.ok(bot);
    assert.equal(bot.type, 'crawler');
    assert.equal(bot.category, BOT_CATEGORY.SEARCH);
    assert.ok(bot.name.toLowerCase().includes('googlebot'));
  });

  it('detects Bingbot', () => {
    const bot = detectBot('Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)');
    assert.ok(bot);
    assert.equal(bot.category, BOT_CATEGORY.SEARCH);
  });

  it('detects GPTBot as AI training', () => {
    const bot = detectBot(
      'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)',
    );
    assert.ok(bot);
    assert.equal(bot.category, BOT_CATEGORY.AI_TRAINING);
  });

  it('detects ClaudeBot as AI training', () => {
    const bot = detectBot(
      'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +https://anthropic.com)',
    );
    assert.ok(bot);
    assert.equal(bot.category, BOT_CATEGORY.AI_TRAINING);
  });

  it('detects ChatGPT-User as AI assistant', () => {
    const bot = detectBot(
      'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ChatGPT-User/1.0; +https://openai.com/bot)',
    );
    assert.ok(bot);
    assert.equal(bot.category, BOT_CATEGORY.AI_ASSISTANT);
  });

  it('detects TwitterBot as social preview', () => {
    const bot = detectBot('Twitterbot/1.0');
    assert.ok(bot);
    assert.equal(bot.category, BOT_CATEGORY.SOCIAL_PREVIEW);
  });

  it('detects WhatsApp as social preview', () => {
    const bot = detectBot('WhatsApp/2.23.20.0');
    assert.ok(bot);
    assert.equal(bot.category, BOT_CATEGORY.SOCIAL_PREVIEW);
  });

  it('detects AhrefsBot as SEO', () => {
    const bot = detectBot('Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)');
    assert.ok(bot);
    assert.equal(bot.category, BOT_CATEGORY.SEO);
  });

  it('detects curl as CLI', () => {
    const bot = detectBot('curl/8.7.1');
    assert.ok(bot);
    assert.equal(bot.type, 'cli');
  });

  it('detects axios as library', () => {
    const bot = detectBot('axios/1.7.2');
    assert.ok(bot);
    assert.equal(bot.type, 'library');
  });

  it('returns null for real browsers', () => {
    assert.equal(
      detectBot(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
      ),
      null,
    );
  });

  it('returns null for empty string', () => {
    assert.equal(detectBot(''), null);
  });
});

describe('isBot()', () => {
  it('true for bots', () => {
    assert.ok(isBot('Googlebot/2.1'));
    assert.ok(isBot('curl/8.0'));
  });

  it('false for browsers', () => {
    assert.ok(!isBot('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36'));
  });
});

describe('isAICrawler()', () => {
  it('true for GPTBot', () => {
    assert.ok(isAICrawler('GPTBot/1.2'));
  });

  it('false for Googlebot', () => {
    assert.ok(!isAICrawler('Googlebot/2.1'));
  });
});

describe('isAIAssistant()', () => {
  it('true for ChatGPT-User', () => {
    assert.ok(isAIAssistant('ChatGPT-User/1.0'));
  });

  it('false for GPTBot (training, not assistant)', () => {
    assert.ok(!isAIAssistant('GPTBot/1.2'));
  });
});

describe('isSearchBot()', () => {
  it('true for Googlebot', () => {
    assert.ok(isSearchBot('Googlebot/2.1'));
  });

  it('false for GPTBot', () => {
    assert.ok(!isSearchBot('GPTBot/1.2'));
  });
});

describe('isSocialPreview()', () => {
  it('true for Twitterbot', () => {
    assert.ok(isSocialPreview('Twitterbot/1.0'));
  });

  it('false for Googlebot', () => {
    assert.ok(!isSocialPreview('Googlebot/2.1'));
  });
});

describe('isSEOBot()', () => {
  it('true for AhrefsBot', () => {
    assert.ok(isSEOBot('AhrefsBot/7.0'));
  });

  it('false for Googlebot', () => {
    assert.ok(!isSEOBot('Googlebot/2.1'));
  });
});

describe('newly added bots', () => {
  it('detects PerplexityBot as search', () => {
    const bot = detectBot('PerplexityBot/1.0');
    assert.equal(bot.name, 'PerplexityBot');
    assert.equal(bot.type, 'crawler');
    assert.equal(bot.category, BOT_CATEGORY.SEARCH);
  });

  it('detects Sogou web spider', () => {
    const bot = detectBot('Sogou web spider/4.0');
    assert.equal(bot.name, 'Sogou web spider');
    assert.equal(bot.type, 'crawler');
    assert.equal(bot.category, BOT_CATEGORY.SEARCH);
  });

  it('detects Daum crawler', () => {
    const bot = detectBot('Daum/4.1');
    assert.equal(bot.name, 'Daum');
    assert.equal(bot.type, 'crawler');
  });

  it('detects Yahoo Japan crawler', () => {
    const bot = detectBot('Y!J-ASR/1.0');
    assert.equal(bot.type, 'crawler');
    assert.equal(bot.category, BOT_CATEGORY.SEARCH);
  });

  it('detects Kangaroo Bot as AI training', () => {
    const bot = detectBot('Kangaroo Bot/1.0');
    assert.equal(bot.type, 'crawler');
    assert.equal(bot.category, BOT_CATEGORY.AI_TRAINING);
  });

  it('detects Amazon Nova Act as AI assistant', () => {
    const bot = detectBot('Agent-NovaAct/1.0');
    assert.equal(bot.name, 'NovaAct');
    assert.equal(bot.type, 'fetcher');
    assert.equal(bot.category, BOT_CATEGORY.AI_ASSISTANT);
  });

  it('detects BLEXBot as SEO', () => {
    const bot = detectBot('BLEXBot/1.0');
    assert.equal(bot.type, 'crawler');
    assert.equal(bot.category, BOT_CATEGORY.SEO);
  });

  it('detects Yandex variants', () => {
    const bot = detectBot('YandexMetrika/4.0');
    assert.equal(bot.type, 'crawler');
    assert.equal(bot.category, BOT_CATEGORY.SEARCH);
  });

  it('detects AdobeAIR as library', () => {
    const bot = detectBot('AdobeAIR/33.0');
    assert.equal(bot.type, 'library');
  });

  it('detects Blueno as monitoring fetcher', () => {
    const bot = detectBot('Blueno/1.0');
    assert.equal(bot.type, 'fetcher');
    assert.equal(bot.category, BOT_CATEGORY.MONITORING);
  });
});
