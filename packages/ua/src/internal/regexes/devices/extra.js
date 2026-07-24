import { MODEL, VENDOR, TYPE, MOBILE, TABLET } from '../../constants.js';

export const extraRules = [
  [
    /(nook)[\w ]+build\/(\w+)/i,
    /(dell) (strea[kpr\d ]*[\dko])/i,
    /(le[- ]+pan)[- ]+(\w{1,9}) bui/i,
    /(trinity)[- ]*(t\d{3}) bui/i,
    /(gigaset)[- ]+(q\w{1,9}) bui/i,
    /(vodafone) ([\w ]+)(?:\)| bui)/i,
  ],
  [VENDOR, MODEL, [TYPE, TABLET]],

  [/(u304aa)/i],
  [MODEL, [VENDOR, 'AT&T'], [TYPE, MOBILE]],

  [/\bsie-(\w*)/i],
  [MODEL, [VENDOR, 'Siemens'], [TYPE, MOBILE]],

  [/\b(rct\w+) b/i],
  [MODEL, [VENDOR, 'RCA'], [TYPE, TABLET]],

  [/\b(venue[\d ]{2,7}) b/i],
  [MODEL, [VENDOR, 'Dell'], [TYPE, TABLET]],

  [/\b(q(?:mv|ta)\w+) b/i],
  [MODEL, [VENDOR, 'Verizon'], [TYPE, TABLET]],

  [/\b(?:barnes[& ]+noble |bn[rt])([\w+ ]*) b/i],
  [MODEL, [VENDOR, 'Barnes & Noble'], [TYPE, TABLET]],

  [/\b(tm\d{3}\w+) b/i],
  [MODEL, [VENDOR, 'NuVision'], [TYPE, TABLET]],

  [/\b(k88) b/i],
  [MODEL, [VENDOR, 'ZTE'], [TYPE, TABLET]],

  [/\b(nx\d{3}j) b/i],
  [MODEL, [VENDOR, 'ZTE'], [TYPE, MOBILE]],

  [/\b(gen\d{3}) b.+49h/i],
  [MODEL, [VENDOR, 'Swiss'], [TYPE, MOBILE]],

  [/\b(zur\d{3}) b/i],
  [MODEL, [VENDOR, 'Swiss'], [TYPE, TABLET]],

  [/^((zeki)?tb.*\b) b/i],
  [MODEL, [VENDOR, 'Zeki'], [TYPE, TABLET]],

  [/\b([yr]\d{2}) b/i, /\b(?:dragon[- ]+touch |dt)(\w{5}) b/i],
  [MODEL, [VENDOR, 'Dragon Touch'], [TYPE, TABLET]],

  [/\b(ns-?\w{0,9}) b/i],
  [MODEL, [VENDOR, 'Insignia'], [TYPE, TABLET]],

  [/\b((nxa|next)-?\w{0,9}) b/i],
  [MODEL, [VENDOR, 'NextBook'], [TYPE, TABLET]],

  [/\b(xtreme_)?(v(1[045]|2[015]|[3469]0|7[05])) b/i],
  [[VENDOR, 'Voice'], MODEL, [TYPE, MOBILE]],

  [/\b(lvtel-)?(v1[12]) b/i],
  [[VENDOR, 'LvTel'], MODEL, [TYPE, MOBILE]],

  [/\b(ph-1) /i],
  [MODEL, [VENDOR, 'Essential'], [TYPE, MOBILE]],

  [/\b(v(100md|700na|7011|917g).*\b) b/i],
  [MODEL, [VENDOR, 'Envizen'], [TYPE, TABLET]],

  [/\b(trio[-\w. ]+) b/i],
  [MODEL, [VENDOR, 'MachSpeed'], [TYPE, TABLET]],

  [/\btu_(1491) b/i],
  [MODEL, [VENDOR, 'Rotor'], [TYPE, TABLET]],
];
