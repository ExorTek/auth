import {
  MODEL,
  VENDOR,
  TYPE,
  SMARTTV,
  SAMSUNG,
  APPLE,
  GOOGLE,
  SONY,
  AMAZON,
  LG,
  NVIDIA,
  XIAOMI,
  SHARP,
} from '../../constants.js';

export const tvRules = [
  // SAMSUNG
  [/smart-?tv.+(samsung)/i, /\b(samsung).+(?:smart-?tv|tizen.*tv)/i],
  [VENDOR, [TYPE, SMARTTV]],

  [/tizen.+tv/i],
  [
    [VENDOR, SAMSUNG],
    [TYPE, SMARTTV],
  ],

  // HISENSE
  [/(hisense).+(?:tv|vidaa)/i],
  [VENDOR, [TYPE, SMARTTV]],

  // VIZIO
  [/(vizio) ?smartcast/i, /(vizio)(?: |.+model\/)(\w+-\w+)/i],
  [VENDOR, MODEL, [TYPE, SMARTTV]],

  // PHILIPS
  [/(philips).+(?:tv|android tv|saphi)/i],
  [VENDOR, [TYPE, SMARTTV]],

  // LG
  [/(nux; netcast.+smarttv|lg (netcast\.tv-201\d|android tv))/i, /web0s/i, /webos.+lg/i],
  [
    [VENDOR, LG],
    [TYPE, SMARTTV],
  ],

  [/tcast.+(lg)e?. ([\w-]+)/i],
  [VENDOR, MODEL, [TYPE, SMARTTV]],

  // APPLE TV
  [/(apple) ?tv/i],
  [VENDOR, [MODEL, 'Apple TV'], [TYPE, SMARTTV]],

  // CHROMECAST
  [/crkey/i],
  [
    [MODEL, 'Chromecast'],
    [VENDOR, GOOGLE],
    [TYPE, SMARTTV],
  ],

  // FIRE TV
  [/droid.+aft(\w+)( bui|\))/i],
  [MODEL, [VENDOR, AMAZON], [TYPE, SMARTTV]],

  // NVIDIA SHIELD
  [/(shield \w+ tv)/i],
  [MODEL, [VENDOR, NVIDIA], [TYPE, SMARTTV]],

  // SONY BRAVIA
  [/(bravia[\w ]+)( bui|\))/i],
  [MODEL, [VENDOR, SONY], [TYPE, SMARTTV]],

  // XIAOMI
  [/(mi(tv|box)-?\w+) bui/i],
  [MODEL, [VENDOR, XIAOMI], [TYPE, SMARTTV]],

  // ROKU
  [/\b(roku)[\dx]*[)\/]((?:dvp-)?[\d.]*)/i],
  [VENDOR, MODEL, [TYPE, SMARTTV]],

  // TCL
  [/(tcl).+(?:tv|android tv|google tv)/i, /\b(tcl)\d{2}[a-z]\d{3}/i],
  [VENDOR, [TYPE, SMARTTV]],

  // SHARP TV
  [/(sharp).+(?:aquos|android tv|google tv)/i],
  [VENDOR, [TYPE, SMARTTV]],

  // PANASONIC
  [/(panasonic).+(?:viera|smart tv|firefox os)/i, /(panasonic).+tv\b/i],
  [VENDOR, [TYPE, SMARTTV]],

  // TOSHIBA
  [/(toshiba).+(?:regza|android tv|tv\b)/i],
  [VENDOR, [TYPE, SMARTTV]],

  // SKYWORTH
  [/(skyworth).+(?:tv|coocaa)/i],
  [VENDOR, [TYPE, SMARTTV]],

  // HAIER
  [/(haier).+tv/i],
  [VENDOR, [TYPE, SMARTTV]],

  // VESTEL
  [/(vestel).+(?:tv|smart)/i],
  [VENDOR, [TYPE, SMARTTV]],

  // GRUNDIG
  [/(grundig).+tv/i],
  [VENDOR, [TYPE, SMARTTV]],

  // CHANGHONG
  [/(changhong).+tv/i],
  [VENDOR, [TYPE, SMARTTV]],

  // KONKA
  [/(konka).+tv/i],
  [VENDOR, [TYPE, SMARTTV]],

  // FUNAI / MAGNAVOX / SANYO / EMERSON (Funai group)
  [/(magnavox|sanyo|emerson|funai).+(?:tv|smart)/i],
  [VENDOR, [TYPE, SMARTTV]],

  // THOMSON
  [/(thomson).+tv/i],
  [VENDOR, [TYPE, SMARTTV]],

  // BANG & OLUFSEN
  [/bang.+olufsen/i],
  [
    [VENDOR, 'Bang & Olufsen'],
    [TYPE, SMARTTV],
  ],

  // LOEWE
  [/(loewe).+tv/i],
  [VENDOR, [TYPE, SMARTTV]],

  // JVC
  [/(jvc).+(?:tv|smart)/i],
  [VENDOR, [TYPE, SMARTTV]],

  // HITACHI
  [/(hitachi).+tv/i],
  [VENDOR, [TYPE, SMARTTV]],

  // INSIGNIA (Best Buy / Fire TV Edition)
  [/insignia.+(?:tv|fire)/i],
  [
    [VENDOR, 'Insignia'],
    [TYPE, SMARTTV],
  ],

  // ELEMENT
  [/element.+tv/i],
  [
    [VENDOR, 'Element'],
    [TYPE, SMARTTV],
  ],

  // POLAROID
  [/polaroid.+tv/i],
  [
    [VENDOR, 'Polaroid'],
    [TYPE, SMARTTV],
  ],

  // ARCELIK / BEKO
  [/arcelik/i, /(beko).+tv/i],
  [
    [VENDOR, 'Arcelik'],
    [TYPE, SMARTTV],
  ],

  // HIMEDIA
  [/himedia/i],
  [
    [VENDOR, 'HiMedia'],
    [TYPE, SMARTTV],
  ],

  // VIDAA (Hisense platform, generic)
  [/vidaa\/\d/i],
  [[TYPE, SMARTTV]],
];
