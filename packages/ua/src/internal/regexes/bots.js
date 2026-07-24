import { NAME, VERSION, TYPE, CRAWLER, FETCHER, CLI, LIBRARY, BOT_CATEGORY } from '../constants.js';

// CRAWLERS

export const crawlerRules = [
  // Search engine crawlers
  [
    /(googlebot|google-inspectiontool|storebot-google)(?:-image|-video|-news)?\/?([\w.]*)/i,
    /(adsbot|apis|mediapartners)-google(?:-mobile)?/i,
  ],
  [NAME, VERSION, [TYPE, CRAWLER]],

  [/(bingbot|adidxbot|bingpreview)\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  [
    /(yandex(?:(?:mobile)?(?:accessibility|additional|com|renderresources|screenshot|sprav)?bot|image(?:s|resizer)|adnet|blogs|favicons|market|media|metrika|news|ontodb(?:api)?|partner|rca|tracker|turbo|verti(?:cal)?s|webmaster|video(?:parser)?))\/([\w.]+)/i,
  ],
  [NAME, VERSION, [TYPE, CRAWLER]],

  [/(baiduspider[-imagevdonwsfcpr]{0,7})\/?([\w.]*)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  [/(duckduckbot|duckduckgo-favicons-bot)\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  [/(applebot(?:-extended)?)\/?([\w.]*)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  [/(seekportbot|mojeekbot|qwantbot(?:-news)?|yepbot|bravebot|kagibot|iaskbot|perplexitybot)\/([\w.-]+)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  [/(seznambot|yeti)\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  [/(sogou (?:pic|head|web|orion|news) spider)\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  [/(coccocbot-(?:image|web))\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  [/(daum(?:oa)?(?:-image)?|hubspot crawler)[ /]([\w.]+)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  [/(y!?j-(?:asr|br[uw]|dscv|mmp|vsidx|wsc))\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  // AI training crawlers
  [/(gptbot|openai-searchbot|openai image downloader)\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  [/(claude(?:bot|-searchbot|-web)|anthropic-ai)\/?([\w.]*)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  [/(deepseekbot|chatglm-spider|kimibot(?:-search)?|pangu(?:bot)?)\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  [/(ccbot|cohere-training-data-crawler)\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  [/(bytespider|tiktokspider|facebookbot|meta-(?:externalagent|externalads|webindexer))\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  [/(amazonbot|amzn-searchbot)\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  [
    /(xai-bot|youbot|petal(?:bot)?|huggingface-bot|replicate-bot|runpod-bot|together-bot|timpibot|sbintuitionsbot|kangaroo bot)\/([\w.]+)/i,
  ],
  [NAME, VERSION, [TYPE, CRAWLER]],

  [/\b(google-extended|google-notebooklm|google-cloudvertexbot|google-other(?:-image|-video)?|google-safety)/i],
  [NAME, [TYPE, CRAWLER]],

  // SEO crawlers
  [/(ahrefsbot|(?:semrush|splitsignal)bot[\w-]*|dotbot|mj12bot|screaming frog seo spider)\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  [/(dataforseobot|brightedge crawler|audisto crawler|siteimprovebot|oncrawl|coveobot|diffbot|turnitinbot)\/([\w.]*)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  [/(algolia crawler(?:[\w ]*)?)\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  [/(blexbot|aihitbot|zumbot)\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  // Archive crawlers
  [/(ia_archiver|archive\.org_bot)\/?([\w.]*)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  [/(webzio(?:-extended)?|omgili(?:bot)?)\/([\w.]*)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  // Advertising
  [/(criteobot|contxbot|baidu-ads)\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  // Security
  [/(virustotal)/i],
  [NAME, [TYPE, CRAWLER]],

  // Catch-all crawlers
  [
    /(360spider(?:-image|-video)?|v0bot|(?:firecrawl|twin)agent|velenpublicwebcrawler|magpie-crawler|cloudflare-autorag|atlassian(?:-|bot)|yacybot|imagesiftbot)\/?([\w.]*)/i,
  ],
  [NAME, VERSION, [TYPE, CRAWLER]],

  [/(ev-crawler)\/([\w.]+)/i],
  [[NAME, 'Headline'], VERSION, [TYPE, CRAWLER]],

  [/(yandexbot\/[\w.]+; mirrordetector)/i],
  [
    [NAME, /\/.+;/gi, ''],
    [TYPE, CRAWLER],
  ],

  [
    /\b(awario(?:smart|rss)?bot|exabot|surdotlybot|swiftbot|onespot-scraper|cotoyogi|freespoke|marginalia|proximic|teoma|elastic|linespider|yisouspider|startpageprivateimageproxy)/i,
  ],
  [NAME, [TYPE, CRAWLER]],

  [/\b(googledocs|google-pagerenderer|googleproducer|siteimprove(?=bot|\.com))/i],
  [NAME, [TYPE, CRAWLER]],

  // Automation / headless browsers
  [/(headlesschrome|phantomjs)\/?([\w.]*)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  [/\b(selenium|playwright|cypress|puppeteer|zombie\.js|nightmare|webdriver)\b/i],
  [NAME, [TYPE, CRAWLER]],

  // Security scanners
  [/(nmap scripting engine|nikto|nessus|acunetix|openvas|masscan|qualys)\/([\w.]*)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  [/\b(shodan|censys|burp suite|aws security scanner|zgrab)\/([\w.]*)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  // Payment webhooks
  [/(stripe)\/([\w.]+)/i, /(braintree-webhooks)\/([\w.]+)/i, /(adyen httpclient)\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, FETCHER]],

  [/paypal ipn/i],
  [
    [NAME, 'PayPal IPN'],
    [TYPE, FETCHER],
  ],

  // Performance tools
  [/(gtmetrix|webpagetest|google page speed insights|pagespeed)\/([\w.]*)/i],
  [NAME, VERSION, [TYPE, FETCHER]],

  [/\b(pingdom)/i],
  [NAME, [TYPE, FETCHER]],

  // Link validators
  [/(w3c-checklink|w3c_validator|broken-link-checker|linkchecker)\/([\w.]*)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],

  // Monitoring / APM
  [/(newrelicpinger|dynatracesynthetic|zabbix|nagios|sentry|datadog agent)\/([\w.]*)/i],
  [NAME, VERSION, [TYPE, FETCHER]],

  // AI agents (coding tools)
  [/(claude-code|manus-user|cursor)\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, FETCHER]],

  // SaaS tools
  [/(hotjar|wappalyzer|whatcms|hubspot marketing grader)\/([\w.]*)/i],
  [NAME, VERSION, [TYPE, CRAWLER]],
];

// FETCHERS

export const fetcherRules = [
  // Social preview fetchers
  [
    /(twitterbot|redditbot|pinterestbot|linkedinbot|discordbot|telegrambot|whatsapp|slackbot(?:-imgproxy|-linkexpanding)?)\/([\w.]+)/i,
  ],
  [NAME, VERSION, [TYPE, FETCHER]],

  [/(bluesky) cardyb\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, FETCHER]],

  [/(facebookexternalhit|facebookcatalog|meta-externalfetcher)\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, FETCHER]],

  [/snap url preview/i],
  [
    [NAME, 'Snapchat Preview'],
    [TYPE, FETCHER],
  ],

  // AI assistant fetchers
  [/(chatgpt-user|amzn-user|claude-user|perplexity-user|mistralai-user|kimi-user|cohere-ai)\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, FETCHER]],

  [/(duckassistbot|gemini-deep-research)\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, FETCHER]],

  [/agent-(novaact)\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, FETCHER]],

  // Monitoring
  [/(uptimerobot|better uptime bot|uptimebot)\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, FETCHER]],

  [/(google-site-verification|feedfetcher-google|googleimageproxy|google-read-aloud)/i],
  [NAME, [TYPE, FETCHER]],

  // Feed fetchers
  [/(feedly(?:bot)?)\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, FETCHER]],

  [/(flipboardproxy)\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, FETCHER]],

  // Misc fetchers
  [/(skypeuripreview) preview\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, FETCHER]],

  [
    /(asana|bitlybot|blueno|bufferlinkpreviewbot|hubspot page fetcher|iframely|rogerbot|siteauditbot|zoombot|vercelbot|vercel(?:flags|tracing|-(favicon|screenshot)-bot))\/([\w.]+)/i,
  ],
  [NAME, VERSION, [TYPE, FETCHER]],

  [/(kakaotalk-scrap|mastodon)\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, FETCHER]],

  [/(yandex(?:calendar|direct(?:dyn)?|fordomain|pagechecker|searchshop)|yadirectfetcher)\/([\w.]+)/i],
  [NAME, VERSION, [TYPE, FETCHER]],

  [
    /((?:better uptime |keybase|telegram|vercel)bot|lighthouse$|gemini-deep-research|google(?:docs|imageproxy|-read-aloud|-pagerenderer|producer)|snap url preview)/i,
  ],
  [NAME, [TYPE, FETCHER]],
];

// CLI TOOLS

export const cliRules = [
  [/(wget|curl|httpie|powershell)[\/ ]\(?([\w.-]+)/i, /(lynx|elinks)[\/ ]([\w.]+)/i],
  [NAME, VERSION, [TYPE, CLI]],
];

// LIBRARIES

export const libraryRules = [
  [
    /^((?:apache|go|java)-http-?client|axios|bun|dart|deno|got|(?:guzzle|lua-resty-|ocaml-co|ok)http|hackney|http\.rb|java|jetty|libwww-perl|needle|node(?:\.js|-fetch|-superagent)|php-soap|postmanruntime|python-(?:httpx|urllib[23]?|requests)|rest-client|scrapy)\/([\w.]+)/i,
    /(aiohttp|jsdom|nutch|undici)\/([\w.-]+)/i,
    /(adobeair)\/([\w.]+)/i,
  ],
  [NAME, VERSION, [TYPE, LIBRARY]],

  [/(node-fetch|phpcrawl|undici)/i],
  [NAME, [TYPE, LIBRARY]],
];

// BOT TAXONOMY MAP

export const botTaxonomy = Object.freeze(
  Object.assign(Object.create(null), {
    // Search
    googlebot: BOT_CATEGORY.SEARCH,
    'googlebot-image': BOT_CATEGORY.SEARCH,
    'googlebot-video': BOT_CATEGORY.SEARCH,
    'googlebot-news': BOT_CATEGORY.SEARCH,
    'storebot-google': BOT_CATEGORY.SEARCH,
    'google-inspectiontool': BOT_CATEGORY.SEARCH,
    bingbot: BOT_CATEGORY.SEARCH,
    adidxbot: BOT_CATEGORY.SEARCH,
    yandexbot: BOT_CATEGORY.SEARCH,
    yandeximages: BOT_CATEGORY.SEARCH,
    yandexvideo: BOT_CATEGORY.SEARCH,
    yandexmedia: BOT_CATEGORY.SEARCH,
    yandexblogs: BOT_CATEGORY.SEARCH,
    yandexnews: BOT_CATEGORY.SEARCH,
    yandexwebmaster: BOT_CATEGORY.SEARCH,
    yandexmetrika: BOT_CATEGORY.SEARCH,
    yandexfavicons: BOT_CATEGORY.SEARCH,
    yandexmarket: BOT_CATEGORY.SEARCH,
    yandexturbo: BOT_CATEGORY.SEARCH,
    yandextracker: BOT_CATEGORY.SEARCH,
    yandexverticals: BOT_CATEGORY.SEARCH,
    yandexontodb: BOT_CATEGORY.SEARCH,
    yandexpartner: BOT_CATEGORY.SEARCH,
    yandexrca: BOT_CATEGORY.SEARCH,
    yandexscreenshotbot: BOT_CATEGORY.SEARCH,
    yandexaccessibilitybot: BOT_CATEGORY.SEARCH,
    yandexadditionalbot: BOT_CATEGORY.SEARCH,
    yandexcombot: BOT_CATEGORY.SEARCH,
    yandexmobileaccessibilitybot: BOT_CATEGORY.SEARCH,
    yandexrenderresourcesbot: BOT_CATEGORY.SEARCH,
    yandexspravbot: BOT_CATEGORY.SEARCH,
    yandexvideoparser: BOT_CATEGORY.SEARCH,
    yandeximageresizer: BOT_CATEGORY.SEARCH,
    baiduspider: BOT_CATEGORY.SEARCH,
    'baiduspider-image': BOT_CATEGORY.SEARCH,
    'baiduspider-video': BOT_CATEGORY.SEARCH,
    duckduckbot: BOT_CATEGORY.SEARCH,
    'duckduckgo-favicons-bot': BOT_CATEGORY.SEARCH,
    applebot: BOT_CATEGORY.SEARCH,
    'applebot-extended': BOT_CATEGORY.SEARCH,
    bravebot: BOT_CATEGORY.SEARCH,
    seekportbot: BOT_CATEGORY.SEARCH,
    mojeekbot: BOT_CATEGORY.SEARCH,
    qwantbot: BOT_CATEGORY.SEARCH,
    'qwantbot-news': BOT_CATEGORY.SEARCH,
    yepbot: BOT_CATEGORY.SEARCH,
    kagibot: BOT_CATEGORY.SEARCH,
    iaskbot: BOT_CATEGORY.SEARCH,
    seznambot: BOT_CATEGORY.SEARCH,
    yeti: BOT_CATEGORY.SEARCH,
    '360spider': BOT_CATEGORY.SEARCH,
    'sogou pic spider': BOT_CATEGORY.SEARCH,
    'sogou head spider': BOT_CATEGORY.SEARCH,
    'sogou web spider': BOT_CATEGORY.SEARCH,
    'sogou orion spider': BOT_CATEGORY.SEARCH,
    'sogou news spider': BOT_CATEGORY.SEARCH,
    'coccocbot-image': BOT_CATEGORY.SEARCH,
    'coccocbot-web': BOT_CATEGORY.SEARCH,
    perplexitybot: BOT_CATEGORY.SEARCH,
    exabot: BOT_CATEGORY.SEARCH,
    teoma: BOT_CATEGORY.SEARCH,
    startpageprivateimageproxy: BOT_CATEGORY.SEARCH,
    'yahoo! slurp': BOT_CATEGORY.SEARCH,

    // Yahoo Japan
    'y!j-asr': BOT_CATEGORY.SEARCH,
    'y!j-brw': BOT_CATEGORY.SEARCH,
    'y!j-bru': BOT_CATEGORY.SEARCH,
    'y!j-dscv': BOT_CATEGORY.SEARCH,
    'y!j-mmp': BOT_CATEGORY.SEARCH,
    'y!j-vsidx': BOT_CATEGORY.SEARCH,
    'y!j-wsc': BOT_CATEGORY.SEARCH,
    'yj-asr': BOT_CATEGORY.SEARCH,
    'yj-brw': BOT_CATEGORY.SEARCH,
    'yj-bru': BOT_CATEGORY.SEARCH,
    'yj-dscv': BOT_CATEGORY.SEARCH,

    // Daum/Naver
    daum: BOT_CATEGORY.SEARCH,
    daumoa: BOT_CATEGORY.SEARCH,
    'daum-image': BOT_CATEGORY.SEARCH,
    linespider: BOT_CATEGORY.SEARCH,
    yisouspider: BOT_CATEGORY.SEARCH,

    // AI Training
    gptbot: BOT_CATEGORY.AI_TRAINING,
    'openai-searchbot': BOT_CATEGORY.AI_TRAINING,
    'openai image downloader': BOT_CATEGORY.AI_TRAINING,
    claudebot: BOT_CATEGORY.AI_TRAINING,
    'claude-searchbot': BOT_CATEGORY.AI_TRAINING,
    'claude-web': BOT_CATEGORY.AI_TRAINING,
    'anthropic-ai': BOT_CATEGORY.AI_TRAINING,
    ccbot: BOT_CATEGORY.AI_TRAINING,
    'cohere-training-data-crawler': BOT_CATEGORY.AI_TRAINING,
    bytespider: BOT_CATEGORY.AI_TRAINING,
    tiktokspider: BOT_CATEGORY.AI_TRAINING,
    deepseekbot: BOT_CATEGORY.AI_TRAINING,
    'chatglm-spider': BOT_CATEGORY.AI_TRAINING,
    amazonbot: BOT_CATEGORY.AI_TRAINING,
    'amzn-searchbot': BOT_CATEGORY.AI_TRAINING,
    'google-extended': BOT_CATEGORY.AI_TRAINING,
    'google-cloudvertexbot': BOT_CATEGORY.AI_TRAINING,
    'google-notebooklm': BOT_CATEGORY.AI_TRAINING,
    facebookbot: BOT_CATEGORY.AI_TRAINING,
    'meta-externalagent': BOT_CATEGORY.AI_TRAINING,
    'meta-externalads': BOT_CATEGORY.AI_TRAINING,
    'meta-webindexer': BOT_CATEGORY.AI_TRAINING,
    'xai-bot': BOT_CATEGORY.AI_TRAINING,
    youbot: BOT_CATEGORY.AI_TRAINING,
    petalbot: BOT_CATEGORY.AI_TRAINING,
    pangubot: BOT_CATEGORY.AI_TRAINING,
    'huggingface-bot': BOT_CATEGORY.AI_TRAINING,
    'replicate-bot': BOT_CATEGORY.AI_TRAINING,
    'runpod-bot': BOT_CATEGORY.AI_TRAINING,
    'together-bot': BOT_CATEGORY.AI_TRAINING,
    timpibot: BOT_CATEGORY.AI_TRAINING,
    sbintuitionsbot: BOT_CATEGORY.AI_TRAINING,
    kimibot: BOT_CATEGORY.AI_TRAINING,
    'kimibot-search': BOT_CATEGORY.AI_TRAINING,
    imagesiftbot: BOT_CATEGORY.AI_TRAINING,
    'kangaroo bot': BOT_CATEGORY.AI_TRAINING,

    // AI Assistants
    'chatgpt-user': BOT_CATEGORY.AI_ASSISTANT,
    'amzn-user': BOT_CATEGORY.AI_ASSISTANT,
    'claude-user': BOT_CATEGORY.AI_ASSISTANT,
    'perplexity-user': BOT_CATEGORY.AI_ASSISTANT,
    'mistralai-user': BOT_CATEGORY.AI_ASSISTANT,
    'kimi-user': BOT_CATEGORY.AI_ASSISTANT,
    'cohere-ai': BOT_CATEGORY.AI_ASSISTANT,
    'gemini-deep-research': BOT_CATEGORY.AI_ASSISTANT,
    duckassistbot: BOT_CATEGORY.AI_ASSISTANT,
    novaact: BOT_CATEGORY.AI_ASSISTANT,

    // Social preview
    twitterbot: BOT_CATEGORY.SOCIAL_PREVIEW,
    redditbot: BOT_CATEGORY.SOCIAL_PREVIEW,
    pinterestbot: BOT_CATEGORY.SOCIAL_PREVIEW,
    linkedinbot: BOT_CATEGORY.SOCIAL_PREVIEW,
    discordbot: BOT_CATEGORY.SOCIAL_PREVIEW,
    telegrambot: BOT_CATEGORY.SOCIAL_PREVIEW,
    whatsapp: BOT_CATEGORY.SOCIAL_PREVIEW,
    slackbot: BOT_CATEGORY.SOCIAL_PREVIEW,
    'slackbot-imgproxy': BOT_CATEGORY.SOCIAL_PREVIEW,
    'slackbot-linkexpanding': BOT_CATEGORY.SOCIAL_PREVIEW,
    facebookexternalhit: BOT_CATEGORY.SOCIAL_PREVIEW,
    facebookcatalog: BOT_CATEGORY.SOCIAL_PREVIEW,
    'meta-externalfetcher': BOT_CATEGORY.SOCIAL_PREVIEW,
    bluesky: BOT_CATEGORY.SOCIAL_PREVIEW,
    'snapchat preview': BOT_CATEGORY.SOCIAL_PREVIEW,
    skypeuripreview: BOT_CATEGORY.SOCIAL_PREVIEW,
    'kakaotalk-scrap': BOT_CATEGORY.SOCIAL_PREVIEW,
    mastodon: BOT_CATEGORY.SOCIAL_PREVIEW,

    // Monitoring
    uptimerobot: BOT_CATEGORY.MONITORING,
    'better uptime bot': BOT_CATEGORY.MONITORING,
    uptimebot: BOT_CATEGORY.MONITORING,
    blueno: BOT_CATEGORY.MONITORING,

    // SEO
    ahrefsbot: BOT_CATEGORY.SEO,
    ahrefssiteaudit: BOT_CATEGORY.SEO,
    semrushbot: BOT_CATEGORY.SEO,
    'semrushbot-ba': BOT_CATEGORY.SEO,
    'semrushbot-si': BOT_CATEGORY.SEO,
    'semrushbot-swa': BOT_CATEGORY.SEO,
    'semrushbot-ct': BOT_CATEGORY.SEO,
    'semrushbot-bm': BOT_CATEGORY.SEO,
    splitsignalbot: BOT_CATEGORY.SEO,
    dotbot: BOT_CATEGORY.SEO,
    mj12bot: BOT_CATEGORY.SEO,
    'screaming frog seo spider': BOT_CATEGORY.SEO,
    dataforseobot: BOT_CATEGORY.SEO,
    'brightedge crawler': BOT_CATEGORY.SEO,
    'audisto crawler': BOT_CATEGORY.SEO,
    siteimprovebot: BOT_CATEGORY.SEO,
    siteimprove: BOT_CATEGORY.SEO,
    oncrawl: BOT_CATEGORY.SEO,
    coveobot: BOT_CATEGORY.SEO,
    blexbot: BOT_CATEGORY.SEO,
    aihitbot: BOT_CATEGORY.SEO,
    zumbot: BOT_CATEGORY.SEO,

    // Advertising
    'adsbot-google': BOT_CATEGORY.ADVERTISING,
    'adsbot-google-mobile': BOT_CATEGORY.ADVERTISING,
    'mediapartners-google': BOT_CATEGORY.ADVERTISING,
    criteobot: BOT_CATEGORY.ADVERTISING,
    contxbot: BOT_CATEGORY.ADVERTISING,
    'baidu-ads': BOT_CATEGORY.ADVERTISING,
    yandexdirect: BOT_CATEGORY.ADVERTISING,
    yandexadnet: BOT_CATEGORY.ADVERTISING,

    // Archiving
    ia_archiver: BOT_CATEGORY.ARCHIVING,
    'archive.org_bot': BOT_CATEGORY.ARCHIVING,
    webzio: BOT_CATEGORY.ARCHIVING,
    'webzio-extended': BOT_CATEGORY.ARCHIVING,

    // Feed
    feedly: BOT_CATEGORY.FEED,
    feedlybot: BOT_CATEGORY.FEED,
    'feedfetcher-google': BOT_CATEGORY.FEED,
    flipboardproxy: BOT_CATEGORY.FEED,

    // Security
    virustotal: BOT_CATEGORY.SECURITY,
    turnitinbot: BOT_CATEGORY.SECURITY,
    'google-safety': BOT_CATEGORY.SECURITY,

    // Automation
    headlesschrome: BOT_CATEGORY.AUTOMATION,
    phantomjs: BOT_CATEGORY.AUTOMATION,
    selenium: BOT_CATEGORY.AUTOMATION,
    playwright: BOT_CATEGORY.AUTOMATION,
    cypress: BOT_CATEGORY.AUTOMATION,
    puppeteer: BOT_CATEGORY.AUTOMATION,
    'zombie.js': BOT_CATEGORY.AUTOMATION,
    nightmare: BOT_CATEGORY.AUTOMATION,
    webdriver: BOT_CATEGORY.AUTOMATION,

    // Security scanners
    'nmap scripting engine': BOT_CATEGORY.SECURITY_SCANNER,
    nikto: BOT_CATEGORY.SECURITY_SCANNER,
    nessus: BOT_CATEGORY.SECURITY_SCANNER,
    acunetix: BOT_CATEGORY.SECURITY_SCANNER,
    openvas: BOT_CATEGORY.SECURITY_SCANNER,
    masscan: BOT_CATEGORY.SECURITY_SCANNER,
    qualys: BOT_CATEGORY.SECURITY_SCANNER,
    shodan: BOT_CATEGORY.SECURITY_SCANNER,
    censys: BOT_CATEGORY.SECURITY_SCANNER,
    'burp suite': BOT_CATEGORY.SECURITY_SCANNER,
    'aws security scanner': BOT_CATEGORY.SECURITY_SCANNER,
    zgrab: BOT_CATEGORY.SECURITY_SCANNER,

    // Payment webhooks
    stripe: BOT_CATEGORY.PAYMENT,
    'paypal ipn': BOT_CATEGORY.PAYMENT,
    'braintree-webhooks': BOT_CATEGORY.PAYMENT,
    'adyen httpclient': BOT_CATEGORY.PAYMENT,

    // Performance tools
    gtmetrix: BOT_CATEGORY.PERFORMANCE,
    webpagetest: BOT_CATEGORY.PERFORMANCE,
    'google page speed insights': BOT_CATEGORY.PERFORMANCE,
    pagespeed: BOT_CATEGORY.PERFORMANCE,
    pingdom: BOT_CATEGORY.PERFORMANCE,

    // Link validators
    'w3c-checklink': BOT_CATEGORY.LINK_VALIDATOR,
    w3c_validator: BOT_CATEGORY.LINK_VALIDATOR,
    'broken-link-checker': BOT_CATEGORY.LINK_VALIDATOR,
    linkchecker: BOT_CATEGORY.LINK_VALIDATOR,

    // Monitoring / APM
    newrelicpinger: BOT_CATEGORY.MONITORING,
    dynatracesynthetic: BOT_CATEGORY.MONITORING,
    zabbix: BOT_CATEGORY.MONITORING,
    nagios: BOT_CATEGORY.MONITORING,
    sentry: BOT_CATEGORY.MONITORING,
    'datadog agent': BOT_CATEGORY.MONITORING,

    // AI agents (coding tools)
    'claude-code': BOT_CATEGORY.AI_AGENT,
    'manus-user': BOT_CATEGORY.AI_AGENT,
    cursor: BOT_CATEGORY.AI_AGENT,

    // SaaS tools
    hotjar: BOT_CATEGORY.GENERIC,
    wappalyzer: BOT_CATEGORY.GENERIC,
    whatcms: BOT_CATEGORY.GENERIC,
    'hubspot marketing grader': BOT_CATEGORY.GENERIC,

    // Generic
    diffbot: BOT_CATEGORY.GENERIC,
    'algolia crawler': BOT_CATEGORY.GENERIC,
    v0bot: BOT_CATEGORY.GENERIC,
    firecrawlagent: BOT_CATEGORY.GENERIC,
    twinagent: BOT_CATEGORY.GENERIC,
    vercelbot: BOT_CATEGORY.GENERIC,
    'cloudflare-autorag': BOT_CATEGORY.GENERIC,
    'hubspot crawler': BOT_CATEGORY.GENERIC,
    cotoyogi: BOT_CATEGORY.GENERIC,
    freespoke: BOT_CATEGORY.GENERIC,
    marginalia: BOT_CATEGORY.GENERIC,
    proximic: BOT_CATEGORY.GENERIC,
    elastic: BOT_CATEGORY.GENERIC,
    atlassianbot: BOT_CATEGORY.GENERIC,
    yacybot: BOT_CATEGORY.GENERIC,
    awariobot: BOT_CATEGORY.GENERIC,
    awarorssbot: BOT_CATEGORY.GENERIC,
    awariosmartbot: BOT_CATEGORY.GENERIC,
    surdotlybot: BOT_CATEGORY.GENERIC,
    swiftbot: BOT_CATEGORY.GENERIC,
    'onespot-scraper': BOT_CATEGORY.GENERIC,
    headline: BOT_CATEGORY.GENERIC,
    'magpie-crawler': BOT_CATEGORY.GENERIC,
    'velenpublicwebcrawler': BOT_CATEGORY.GENERIC,
    'hubspot page fetcher': BOT_CATEGORY.GENERIC,
    iframely: BOT_CATEGORY.GENERIC,
    rogerbot: BOT_CATEGORY.GENERIC,
    asana: BOT_CATEGORY.GENERIC,
  }),
);
