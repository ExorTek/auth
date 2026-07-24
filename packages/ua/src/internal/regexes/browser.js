import { NAME, VERSION, TYPE, INAPP, FETCHER, EMAIL, MEDIAPLAYER, FEEDREADER } from '../constants.js';

const M_CHROME = 'Mobile Chrome';
const M_SAFARI = 'Mobile Safari';
const M_FIREFOX = 'Mobile Firefox';
const B = ' Browser';

export const browserRules = [
  // Chromium-based (most common first)

  [/\b(?:crmo|crios)\/([\w.]+)/i],
  [VERSION, [NAME, M_CHROME]],

  [/edg(?:e|ios|a)?\/([\w.]+)/i],
  [VERSION, [NAME, 'Edge']],

  [/(brave)(?: chrome)?\/([\d.]+)/i],
  [NAME, VERSION],

  [/arcbrowser\/([\w.]+)/i],
  [VERSION, [NAME, 'Arc']],

  [/(vivaldi)\/([\w.]+)/i],
  [NAME, VERSION],

  [/(midori)\/([\w.]+)/i],
  [NAME, VERSION],

  [/(falkon)\/([\w.]+)/i],
  [NAME, VERSION],

  [/\bopr\/([\w.]+)/i],
  [VERSION, [NAME, 'Opera']],

  [/opios[\/ ]+([\w.]+)/i],
  [VERSION, [NAME, 'Opera Mini']],

  [
    /(opera mini)\/([\w.-]+)/i,
    /(opera [mobiletab]{3,6})\b.+version\/([\w.-]+)/i,
    /(opera)(?:.+version\/|[\/ ]+)([\w.]+)/i,
  ],
  [NAME, VERSION],

  [/\b(yabrowser|yowser)\/([\w.]+)/i],
  [[NAME, 'Yandex'], VERSION],

  [/ya(?:search)?browser\/([\w.]+)/i],
  [VERSION, [NAME, 'Yandex']],

  [/(duckduckgo)\/([\w.]+)/i, /\bddg\/([\w.]+)/i],
  [VERSION, [NAME, 'DuckDuckGo']],

  [/samsungbrowser\/([\w.]+)/i],
  [VERSION, [NAME, 'Samsung Internet']],

  [/(whale(?!.+naver))\/([\w.-]+)/i],
  [NAME, VERSION],

  [/(puffin)\/([\w.-]+)/i],
  [NAME, VERSION],

  [/(?:uc ?browser|ucweb)[\/ ]?([\w.]+)/i],
  [VERSION, [NAME, 'UCBrowser']],

  [/micromessenger\/([\w.]+)/i],
  [VERSION, [NAME, 'WeChat']],

  [/(qqbrowser|qq)\/([\w.]+)/i],
  [[NAME, 'QQBrowser'], VERSION],

  [/quark(?:pc)?\/([\w.-]+)/i],
  [VERSION, [NAME, 'Quark']],

  // In-app browsers

  [/((?:fban\/fbios|fb_iab\/fb4a)(?!.+fbav)|;fbav\/([\w.]+);)/i],
  [[NAME, 'Facebook'], VERSION, [TYPE, INAPP]],

  [/(instagram|snapchat|tiktok|kakao(?:talk|story)|klarna)[\/ ]([\w.-]+)/i],
  [NAME, VERSION, [TYPE, INAPP]],

  [/\bgsa\/([\w.]+) .*safari\//i],
  [VERSION, [NAME, 'GSA'], [TYPE, INAPP]],

  [/(?:musical_ly|trill)(?:.+app_?version\/|_)([\w.]+)/i],
  [VERSION, [NAME, 'TikTok'], [TYPE, INAPP]],

  [/\[(linkedin)app\]/i],
  [NAME, [TYPE, INAPP]],

  [/(telegram|discord|slack|teams|notion)[\/ ]([\w.-]+)/i],
  [NAME, VERSION, [TYPE, INAPP]],

  [
    /\b(discord|figma|mattermost|notion|postman|rambox|rocket\.chat|slack|teams)\/([\w.]+).+(?:electron\/|; ios)/i,
    /(flipboard)\/([\w.]+)/i,
  ],
  [NAME, VERSION, [TYPE, INAPP]],

  [/(evernote) win/i, /(teams)mobile-(?:ios|and)/i],
  [NAME, [TYPE, INAPP]],

  [/chatlyio\/([\d.]+)/i],
  [VERSION, [NAME, 'Slack'], [TYPE, INAPP]],

  [/ultralite app_version\/([\w.]+)/i],
  [VERSION, [NAME, 'TikTok Lite'], [TYPE, INAPP]],

  [/\) code\/([\d.]+).+electron\//i],
  [VERSION, [NAME, 'VS Code'], [TYPE, INAPP]],

  [/jp\.co\.yahoo\.(?:android\.yjtop|ipn\.appli)\/([\d.]+)/i],
  [VERSION, [NAME, 'Yahoo! Japan'], [TYPE, INAPP]],

  // WebView

  [/wv\).+chrome\/([\w.]+)/i],
  [VERSION, [NAME, 'Chrome WebView'], [TYPE, INAPP]],

  [/; wv\).+(chrome)\/([\w.]+)/i],
  [[NAME, 'Chrome WebView'], VERSION, [TYPE, INAPP]],

  // Gecko-based

  [/(?:mobile|tablet);.*(firefox)\/([\w.-]+)/i],
  [[NAME, M_FIREFOX], VERSION],

  [/(librewolf|waterfox|palemoon|basilisk|seamonkey|icecat)\/([\w.-]+)/i],
  [NAME, VERSION],

  [/\bfocus\/([\w.]+)/i],
  [VERSION, [NAME, 'Firefox Focus']],

  [/fxios\/([\w.-]+)/i],
  [VERSION, [NAME, M_FIREFOX]],

  [/(firefox)\/([\w.]+)/i],
  [NAME, VERSION],

  // Safari / WebKit

  [/version\/([\w.,]+) .*mobile(?:\/\w+ | ?)safari/i],
  [VERSION, [NAME, M_SAFARI]],

  [/iphone .*mobile(?:\/\w+ | ?)safari/i],
  [[NAME, M_SAFARI]],

  [/version\/([\w.,]+) .*(safari)/i],
  [VERSION, NAME],

  // IE / Trident

  [/trident.+rv[: ]([\w.]{1,9})\b.+like gecko/i],
  [VERSION, [NAME, 'IE']],

  [/(?:ms|\()(ie) ([\w.]+)/i],
  [NAME, VERSION],

  // Other Chromium

  [/(chromium)\/([\w.-]+)/i],
  [NAME, VERSION],

  [/headlesschrome(?:\/([\w.]+)| )/i],
  [VERSION, [NAME, 'Chrome Headless']],

  [/droid.+ version\/([\w.]+)\b.+(?:mobile safari|safari)/i],
  [VERSION, [NAME, 'Android' + B]],

  [/chrome\/([\w.]+) mobile/i],
  [VERSION, [NAME, M_CHROME]],

  [/(chrome|omniweb|arora)\/v?([\w.]+)/i],
  [NAME, VERSION],

  // Other / legacy

  [
    /(atlas|flock|rockmelt|midori|epiphany|silk|skyfire|bolt|iron|iridium|phantomjs|bowser|qupzilla|falkon|rekonq|dooble|(?:hi|lg|ovi|qute)browser|helio)\/v?([\w.-]+)/i,
  ],
  [NAME, VERSION],

  [/(aloha|heytap|surf|qwant)browser\/([\d.]+)/i],
  [NAME, VERSION],

  [/(ecosia|weibo)(?:__| \w+@)([\d.]+)/i],
  [NAME, VERSION],

  [/(konqueror)\/([\w.]+)/i],
  [NAME, VERSION],

  [/(webkit|khtml)\/([\w.]+)/i],
  [NAME, VERSION],

  [/(navigator|netscape\d?)\/([\w.-]+)/i],
  [[NAME, 'Netscape'], VERSION],

  [/(cobalt)\/([\w.]+)/i],
  [NAME, VERSION],

  [/(mozilla)\/([\w.]+(?= .+rv:.+gecko\/\d+)|[0-4][\w.]+(?!.+compatible))/i],
  [NAME, VERSION],

  [
    /(amaya|dillo|doris|icab|ladybird|lynx|mosaic|netsurf|obigo|polaris|w3m|(?:go|ice|up)[. ]?browser)[-/ ]?v?([\w.]+)/i,
    /\b(links) \(([\w.]+)/i,
  ],
  [NAME, [VERSION, /_/g, '.']],

  // Email clients

  [/(android)\/([\w.-]+email)/i],
  [NAME, VERSION, [TYPE, EMAIL]],

  [
    new RegExp(
      '(' +
        '(?:air|aqua|blue|claws|daum|fair|fox|k-9|mac|nylas|pegasus|poco|poly|proton|samsung|squirrel|yahoo) ?e?mail(?:-desktop| app| bridge)?|' +
        'microsoft outlook|r2mail2|spicebird|turnpike|yahoomobile|' +
        '(?:microsoft )?outlook(?:-express)?|macoutlook|windows-live-mail|' +
        'alpine|balsa|barca|canary|emclient|eudora|evolution|geary|gnus|' +
        'horde::imp|incredimail|kmail2?|kontact|lotus-notes|' +
        'mail(?:bird|mate|spring)|mutt|navermailapp|newton|nine|postbox|' +
        'rainloop|roundcube webmail|spar(?:row|kdesktop)|sylpheed|' +
        'the bat!|thunderbird|trojita|tutanota-desktop|wanderlust|' +
        'zdesktop|zohomail-desktop' +
        ')' +
        '(?:m.+ail; |[\\/ ])' +
        '([\\w\\.-]+)',
      'i',
    ),
  ],
  [
    [
      NAME,
      str => {
        const map = {
          YahooMobile: 'Yahoo Mail',
          YahooMail: 'Yahoo Mail',
          'K-9': 'K-9 Mail',
          'K-9 Mail': 'K-9 Mail',
          Zdesktop: 'Zimbra',
          zdesktop: 'Zimbra',
        };
        return map[str] || str;
      },
    ],
    VERSION,
    [TYPE, EMAIL],
  ],

  [/(mail)\/([\w.]+) cf/i],
  [NAME, VERSION, [TYPE, EMAIL]],

  [/(zimbra)\/([\w.-]+)/i],
  [NAME, VERSION, [TYPE, EMAIL]],

  // Media players

  [
    /(apple(?:coremedia|tv))\/([\w._]+)/i,
    /(coremedia) v([\w._]+)/i,
    /(ares|clementine|music player daemon|nexplayer|ossproxy) ([\w.-]+)/i,
    /^(aqualung|audacious|audimusicstream|amarok|bass|bsplayer|core|gnomemplayer|gvfs|irapp|lyssna|music on console|nero (?:home|scout)|nokia\d+|nsplayer|psp-internetradioplayer|quicktime|rma|radioapp|radioclientapplication|soundtap|stagefright|streamium|totem|videos|xbmc|xine|xmms)\/([\w.-]+)/i,
    /(lg player|nexplayer) ([\d.]+)/i,
    /player\/(nexplayer|lg player) ([\w.-]+)/i,
    /(gstreamer) souphttpsrc.+libsoup\/([\w.-]+)/i,
    /(htc streaming player) [\w_]+ \/ ([\d.]+)/i,
    /(lavf)([\d.]+)/i,
    /(mplayer)(?: |\/)(?:(?:sherpya-)?svn)(?:-| )(r\d+(?:-\d+[\w.-]+))/i,
    / (songbird)\/([\w.-]+)/i,
    /(winamp)(?:3 version|mpeg| ) ([\w.-]+)/i,
    /(vlc)(?:\/| media player - version )([\w.-]+)/i,
    /^(foobar2000|itunes|smp)\/([\d.]+)/i,
    /com\.(riseupradioalarm)\/([\d.]*)/i,
    /(mplayer)(?:\s|\/| unknown-)([\w.-]+)/i,
    /(windows)\/([\w.-]+) upnp\/[\d.]+ dlnadoc\/[\d.]+ home media server/i,
  ],
  [NAME, VERSION, [TYPE, MEDIAPLAYER]],

  [/(flrp)\/([\w.-]+)/i],
  [[NAME, 'Flip Player'], VERSION, [TYPE, MEDIAPLAYER]],

  [
    /(fstream|media player classic|inlight radio|mplayer|nativehost|nero showtime|ocms-bot|queryseekspider|tapinradio|tunein radio|winamp|yourmuze)/i,
  ],
  [NAME, [TYPE, MEDIAPLAYER]],

  [/(htc_one_s|windows-media-player|wmplayer)\/([\w.-]+)/i],
  [[NAME, /[_-]/g, ' '], VERSION, [TYPE, MEDIAPLAYER]],

  [/(rad\.io|radio\.(?:de|at|fr)) ([\d.]+)/i],
  [[NAME, 'rad.io'], VERSION, [TYPE, MEDIAPLAYER]],

  // Feed readers

  [
    /(reeder|netnewswire|newsblur|feeddler|newsboat|gpodder|podcast addict|rssowl|akregator|liferea|miniflux|inoreader|theoldreader|bazqux|feedbin)\/([\w.-]+)/i,
  ],
  [NAME, VERSION, [TYPE, FEEDREADER]],

  // Electron-based

  [/(electron)\/([\w.]+) safari/i],
  [NAME, VERSION],

  // Tesla

  [/(tesla)(?: qtcarbrowser|\/(20\d\d\.[\w.-]+))/i],
  [NAME, VERSION],

  // Lighthouse

  [/ome-(lighthouse)$/i],
  [NAME, [TYPE, FETCHER]],
];
