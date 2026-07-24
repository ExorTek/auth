import { NAME, VERSION } from '../constants.js';
import { mapStr } from '../helpers.js';

const WINDOWS = 'Windows';
const MACOS = 'macOS';
const IOS = 'iOS';

const windowsVersionMap = {
  ME: '4.90',
  'NT 3.51': '3.51',
  'NT 4.0': '4.0',
  2000: ['5.0', '5.01'],
  XP: ['5.1', '5.2'],
  Vista: '6.0',
  7: '6.1',
  8: '6.2',
  '8.1': '6.3',
  10: ['6.4', '10.0'],
  NT: '',
};

export const osRules = [
  // Windows

  [/(windows nt) (6\.[23]); arm/i],
  [
    [NAME, /N/, 'R'],
    [VERSION, v => mapStr(v, windowsVersionMap)],
  ],

  [
    /(windows (?:phone|mobile|iot))(?: os)?[\/ ]?([\d.]*( se)?)/i,
    /(windows)[\/ ](1[01]|2000|3\.1|7|8(\.1)?|9[58]|me|server 20\d\d( r2)?|vista|xp)/i,
  ],
  [NAME, VERSION],

  [/windows nt ?([\d.)]*)/i, /\bwin(?=3| ?9|n)(?:nt| 9x )?([\d.;]*)/i],
  [
    [VERSION, v => mapStr(v.replace(/[;)]/g, ''), windowsVersionMap)],
    [NAME, WINDOWS],
  ],

  [/(windows ce)\/?([\d.]*)/i],
  [NAME, VERSION],

  // iOS / macOS

  [
    /[adehimnop]{4,7}\b(?:.*os ([\w]+) like mac|; opera)/i,
    /(?:ios;fbsv|ios(?=.+ip(?:ad|hone)|.+apple ?tv)|ip(?:ad|hone)(?: |.+i(?:pad)?)os|apple ?tv.+ios)[\/ ]([\w.]+)/i,
    /\btvos ?([\w.]+)/i,
    /cfnetwork\/.+darwin/i,
  ],
  [
    [VERSION, /_/g, '.'],
    [NAME, IOS],
  ],

  [/(mac os x) ?([\w. ]*)/i, /(macintosh|mac_powerpc\b)(?!.+(haiku|morphos))/i],
  [
    [NAME, MACOS],
    [VERSION, /_/g, '.'],
  ],

  // Android

  [/droid ([\w.]+)\b.+(android[- ]x86)/i],
  [VERSION, NAME],

  [
    /(harmonyos)[\/ ]?([\d.]*)/i,
    /(android|bada|blackberry|kaios|maemo|meego|openharmony|qnx|rim tablet os|sailfish|series40|symbian|tizen)\w*[-/.; ]?([\d.]*)/i,
  ],
  [NAME, VERSION],

  [/\(bb(10);/i],
  [VERSION, [NAME, 'BlackBerry']],

  [/(?:symbian ?os|symbos|s60(?=;)|series ?60)[-/ ]?([\w.]*)/i],
  [VERSION, [NAME, 'Symbian']],

  // Mobile OS

  [/mozilla\/[\d.]+ \((?:mobile|tablet|tv|[^)]*(?:viera|lg)).*?rv:([\w.]+)\).+gecko\//i],
  [VERSION, [NAME, 'Firefox OS']],

  [/\b(?:hp)?wos(?:browser)?\/([\w.]+)/i, /webos(?:[ /]?|\.tv-20(?=2[2-9]))(\d[\d.]*)/i],
  [VERSION, [NAME, 'webOS']],

  [/watch(?: ?os[,/]|\d,\d\/)([\d.]+)/i],
  [VERSION, [NAME, 'watchOS']],

  // Chrome OS

  [/cros [\w]+(?:\)| ([\w.]+)\b)/i],
  [VERSION, [NAME, 'Chrome OS']],

  // Desktop Linux / Unix

  [/linux.+(mint)[/() ]?([\w.]*)/i],
  [NAME, VERSION],

  [/(ubuntu) ([\w.]+) like android/i],
  [[NAME, 'Ubuntu Touch'], VERSION],

  [
    /([kxln]?ubuntu|debian|suse|opensuse|gentoo|slackware|fedora|mandriva|centos|pclinuxos|red ?hat|zenwalk|linpus|raspbian|plan 9|minix|risc os|contiki|deepin|manjaro|elementary os|sabayon|linspire|knoppix)(?: gnu[/ ]linux)?(?: enterprise)?(?:[- ]linux)?(?:-gnu)?[-/ ]?(?!chrom|package)([\w.-]*)/i,
    /(mageia|vectorlinux|fuchsia|arcaos|arch(?= ?linux))[;l ]([\d.]*)/i,
  ],
  [NAME, VERSION],

  [/((?:open)?solaris)[-/ ]?([\w.]*)/i],
  [NAME, VERSION],

  [/\b(aix)[; ]([1-9.]{0,4})/i],
  [NAME, VERSION],

  [/(hurd|linux|morphos)(?: (?:arm|x86|ppc)\w*| ?)([\w.]*)/i, /(gnu) ?([\w.]*)/i],
  [NAME, VERSION],

  [/\b([-frentopcghs]{0,5}bsd|dragonfly)[\/ ]?(?!amd|[ix346]{1,2}86)([\w.]*)/i],
  [NAME, VERSION],

  [/(haiku) ?(r\d)?/i],
  [NAME, VERSION],

  [/(sunos) ?([\d.]*)/i],
  [[NAME, 'Solaris'], VERSION],

  [/\b(beos|os\/2|amigaos|openvms|hp-ux|serenityos)/i, /(unix) ?([\w.]*)/i],
  [NAME, VERSION],

  // Console / Smart TV OS

  [/(nintendo|playstation) (\w+)/i, /(xbox); +xbox ([^);]+)/i, /(pico) .+os([\w.]+)/i],
  [NAME, VERSION],
];
