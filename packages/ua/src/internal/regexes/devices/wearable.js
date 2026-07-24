import { MODEL, VENDOR, TYPE, WEARABLE, SAMSUNG, APPLE, MOTOROLA } from '../../constants.js';

export const wearableRules = [
  [/\b(sm-[lr]\d\d[0156][fnuw]?s?|gear live)\b/i],
  [MODEL, [VENDOR, SAMSUNG], [TYPE, WEARABLE]],

  [/(asus|google|lg|oppo|xiaomi) ((pixel |zen)?watch[\w ]*)(?: bui|\))/i],
  [VENDOR, MODEL, [TYPE, WEARABLE]],

  [/(watch)(?: ?os[,/]|\d,\d\/)([\d.]+)/i],
  [MODEL, [VENDOR, APPLE], [TYPE, WEARABLE]],

  [/(moto 360)/i],
  [MODEL, [VENDOR, MOTOROLA], [TYPE, WEARABLE]],
];
