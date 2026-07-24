import {
  MODEL,
  VENDOR,
  TYPE,
  MOBILE,
  TABLET,
  SAMSUNG,
  APPLE,
  HUAWEI,
  XIAOMI,
  GOOGLE,
  SONY,
  AMAZON,
  LG,
  MOTOROLA,
  LENOVO,
  ASUS,
  ONEPLUS,
  OPPO,
  BLACKBERRY,
  SHARP,
  HONOR,
} from '../../constants.js';

export const mobileRules = [
  // SAMSUNG

  [/\b(sch-i[89]0\d|shw-m380s|sm-[ptx]\w{2,4}|gt-[pn]\d{2,4}|sgh-t8[56]9|nexus 10)/i],
  [MODEL, [VENDOR, SAMSUNG], [TYPE, TABLET]],

  [
    /\b((?:s[cgp]h|gt|sm)-(?![lr])\w+|sc[g-]?[\d]+a?|galaxy nexus)/i,
    /samsung[- ]((?!sm-[lr]|browser)[\w-]+)/i,
    /sec-(sgh\w+)/i,
  ],
  [MODEL, [VENDOR, SAMSUNG], [TYPE, MOBILE]],

  // APPLE

  [/(?:\/|\()(ip(?:hone|od)[\w, ]*)[/);]/i],
  [MODEL, [VENDOR, APPLE], [TYPE, MOBILE]],

  [/\b(?:ios|apple\w+)\/.+[(/](ipad)/i, /\b(ipad)[\d,]*[;\] ].+(mac |i(pad)?)os/i],
  [MODEL, [VENDOR, APPLE], [TYPE, TABLET]],

  [/(macintosh);/i],
  [MODEL, [VENDOR, APPLE]],

  // HONOR

  [/\b((?:brt|eln|hey2?|gdi|jdn)-a?[lnw]09|(?:ag[rm]3?|jdn2|kob2)-a?[lw]0[09]hn)(?: bui|\)|;)/i],
  [MODEL, [VENDOR, HONOR], [TYPE, TABLET]],

  [/honor([\w- ]+)[;)]/i],
  [MODEL, [VENDOR, HONOR], [TYPE, MOBILE]],

  // HUAWEI

  [
    /\b((?:ag[rs][2356]?k?|bah[234]?|bg[2o]|bt[kv]|cmr|cpn|db[ry]2?|jdn2|got|kob2?k?|mon|pce|scm|sht?|[tw]gr|vrd)-[ad]?[lw][0125][09]b?|605hw|bg2-u03|(?:gem|fdr|m2|ple|t1)-[7a]0[1-4][lu]|t1-a2[13][lw]|mediapad[\w. ]*(?= bui|\)))\b(?!.+d\/s)/i,
  ],
  [MODEL, [VENDOR, HUAWEI], [TYPE, TABLET]],

  [/(?:huawei) ?([\w- ]+)[;)]/i, /\b(nexus 6p|\w{2,4}e?-[atu]?[ln][\dx][\dc][adnt]?)\b(?!.+d\/s)/i],
  [MODEL, [VENDOR, HUAWEI], [TYPE, MOBILE]],

  // XIAOMI

  [
    /oid[^)]+; (2[\dbc]{4}(182|283|rp\w{2})[cgl]|m2105k81a?c)(?: bui|\))/i,
    /\b(?:xiao)?((?:red)?mi[-_ ]?pad[\w- ]*)(?: bui|\))/i,
  ],
  [
    [MODEL, /_/g, ' '],
    [VENDOR, XIAOMI],
    [TYPE, TABLET],
  ],

  [
    /\b; (\w+) build\/hm\1/i,
    /\b(hm[-_ ]?note?[_ ]?(?:\d\w)?) bui/i,
    /oid[^)]+; (redmi[\-_ ]?(?:note|k)?[\w_ ]+|m?[12]\d[01]\d\w{3,6}|poco[\w ]+|(shark )?\w{3}-[ah]0|qin ?[1-3](s\+|ultra| pro)?)( bui|; wv|\))/i,
    /\b(mi[-_ ]?(?:a\d|one|one[_ ]plus|note|max|cc)?[_ ]?(?:\d{0,2}\w?)[_ ]?(?:plus|se|lite|pro)?( 5g|lte)?)(?: bui|\))/i,
    /; ([\w ]+) miui\/v?\d/i,
  ],
  [
    [MODEL, /_/g, ' '],
    [VENDOR, XIAOMI],
    [TYPE, MOBILE],
  ],

  // ONEPLUS

  [
    /droid.+; (cph2[3-6]\d[13579]|((gm|hd)19|(ac|be|in|kb)20|(d[en]|eb|le|mt)21|ne22)[0-2]\d|p[g-l]\w[1m]10)\b/i,
    /(?:one)?(?:plus)? (a\d0\d\d)(?: b|\))/i,
  ],
  [MODEL, [VENDOR, ONEPLUS], [TYPE, MOBILE]],

  // OPPO

  [/; (\w+) bui.+ oppo/i, /\b(cph[12]\d{3}|p(?:af|c[al]|d\w|e[ar])[mt]\d0|x9007|a101op)\b/i],
  [MODEL, [VENDOR, OPPO], [TYPE, MOBILE]],

  // GOOGLE

  [/(pixel (c|tablet))\b/i],
  [MODEL, [VENDOR, GOOGLE], [TYPE, TABLET]],

  [/droid.+;(?: google)? (pixel[\d ]*a?( pro)?( xl)?( fold)?( \(5g\))?|g\w{4,})( bui|\))/i],
  [MODEL, [VENDOR, GOOGLE], [TYPE, MOBILE]],

  // SONY

  [/droid.+; (a?\d[0-2]{2}so|[c-g]\d{4}|so[-gl]\w+|xq-\w\w\d\d)(?= bui|\))/i],
  [MODEL, [VENDOR, SONY], [TYPE, MOBILE]],

  [/sony tablet [ps]/i, /\b(?:sony)?sgp\w+(?: bui|\))/i],
  [
    [MODEL, 'Xperia Tablet'],
    [VENDOR, SONY],
    [TYPE, TABLET],
  ],

  // AMAZON

  [/(alexa)webm/i, /(kf[a-z]{2}wi|aeo(?!bc)\w\w)( bui|\))/i, /(kf[a-z]+)( bui|\)).+silk\//i],
  [MODEL, [VENDOR, AMAZON], [TYPE, TABLET]],

  [/((?:sd|kf)[0349hijorstuw]+)( bui|\)).+silk\//i],
  [
    [MODEL, /(.+)/g, 'Fire Phone $1'],
    [VENDOR, AMAZON],
    [TYPE, MOBILE],
  ],

  // BLACKBERRY

  [/(playbook);[\w-),; ]+(rim)/i],
  [MODEL, VENDOR, [TYPE, TABLET]],

  [/\b((?:bb[a-f]|st[hv])100-\d)/i, /(?:blackberry|\(bb10;) (\w+)/i],
  [MODEL, [VENDOR, BLACKBERRY], [TYPE, MOBILE]],

  // ASUS

  [/(?:\b|asus_)(transfo[prime ]{4,10} \w+|eeepc|slider \w+|nexus 7|padfone|p00[cj])/i],
  [MODEL, [VENDOR, ASUS], [TYPE, TABLET]],

  [/ (z[bes]6[027][012][km][ls]|zenfone \d\w?)\b/i],
  [MODEL, [VENDOR, ASUS], [TYPE, MOBILE]],

  // LG

  [/\b(?:lg)?([vl]k-?\d{3}) bui| 3\.[\w-; ]{10}lg?-([06cv9]{3,4})/i],
  [MODEL, [VENDOR, LG], [TYPE, TABLET]],

  [
    /(lm(?:-?f100[nv]?|-[\w.]+)(?= bui|\))|nexus [45])/i,
    /\blg[-e;/ ]+(?!.*(?:browser|netcast|android tv|watch|webos))(\w+)/i,
    /\blg-?([\d\w]+) bui/i,
  ],
  [MODEL, [VENDOR, LG], [TYPE, MOBILE]],

  // MOTOROLA

  [
    /\b(milestone|droid(?:[2-4x]| (?:bionic|x2|pro|razr))?:?( 4g)?)\b[\w ]+build\//i,
    /\bmot(?:orola)?[- ]([\w\s]+)(\)| bui)/i,
    /((?:moto(?! 360)[\w-() ]+|xt\d{3,4}[cgkosw+]?[\d-]*|nexus 6)(?= bui|\)))/i,
  ],
  [MODEL, [VENDOR, MOTOROLA], [TYPE, MOBILE]],

  // LENOVO

  [
    /(ideatab[\w- ]+|602lv|d-42a|a101lv|a2109a|a3500-hv|s[56]000|pb-6505[my]|tb-?x?\d{3,4}(?:f[cu]|xu|[av])|yt\d?-[jx]?\d+[lfmx])( bui|;|\)|\/)/i,
    /lenovo ?(b[68]0[08]0-?[hf]?|tab(?:[\w- ]+?)|tb[\w-]{6,7})( bui|;|\)|\/)/i,
  ],
  [MODEL, [VENDOR, LENOVO], [TYPE, TABLET]],

  [/lenovo[-_ ]?([\w- ]+?)(?: bui|\)|\/)/i],
  [MODEL, [VENDOR, LENOVO], [TYPE, MOBILE]],

  // NOKIA

  [/(nokia) (t[12][01])/i],
  [VENDOR, MODEL, [TYPE, TABLET]],

  [/(?:maemo|nokia).*(n900|lumia \d+|rm-\d+)/i, /nokia[-_ ]?(([\w-. ]*?))( bui|\)|;|\/)/i],
  [
    [MODEL, /_/g, ' '],
    [TYPE, MOBILE],
    [VENDOR, 'Nokia'],
  ],

  // SHARP

  [/\b(sh-?[altvz]?\d\d[a-ekm]?)/i],
  [MODEL, [VENDOR, SHARP], [TYPE, MOBILE]],

  // HTC

  [/(nexus 9)/i],
  [MODEL, [VENDOR, 'HTC'], [TYPE, TABLET]],

  [/(htc)[-;_ ]{1,2}([\w ]+(?=\)| bui)|\w+)/i],
  [VENDOR, [MODEL, /_/g, ' '], [TYPE, MOBILE]],

  // ZTE

  [/(zte)[- ]([\w ]+?)(?: bui|\/|\))/i],
  [VENDOR, [MODEL, /_/g, ' '], [TYPE, MOBILE]],

  // MIXED VENDORS

  [
    /(blackberry|benq|palm(?=-)|sonyericsson|acer|asus(?! zenw)|dell|jolla|meizu|motorola|polytron|tecno|micromax|advan)[-_ ]?([\w-]*)/i,
    /; (blu|coolpad|cubot|hmd|imo|infinix|lava|oneplus|tcl|wiko)[_ ]([\w-+ ]+?)(?: bui|\)|; r)/i,
    /(hp) ([\w ]+\w)/i,
    /(microsoft); (lumia[\w ]+)/i,
    /(oppo) ?([\w ]+) bui/i,
    /(hisense) ([ehv][\w ]+)\)/i,
  ],
  [VENDOR, MODEL, [TYPE, MOBILE]],

  [/(kobo)\s(ereader|touch)/i, /(hp).+(touchpad(?!.+tablet)|tablet)/i, /(kindle)\/([\w.]+)/i],
  [VENDOR, MODEL, [TYPE, TABLET]],
];
