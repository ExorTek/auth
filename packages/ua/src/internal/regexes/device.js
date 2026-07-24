import { MODEL, VENDOR, TYPE, MOBILE, TABLET, SMARTTV, XR, EMBEDDED, AMAZON, APPLE } from '../constants.js';
import { lower } from '../helpers.js';
import { tvRules } from './devices/tv.js';
import { consoleRules } from './devices/console.js';
import { xrRules } from './devices/xr.js';
import { mobileRules } from './devices/mobile.js';
import { wearableRules } from './devices/wearable.js';
import { vehicleRules } from './devices/vehicle.js';
import { extraRules } from './devices/extra.js';
import { iotRules } from './devices/iot.js';

export const deviceRules = [
  ...tvRules,
  ...consoleRules,
  ...xrRules,
  ...mobileRules,
  ...wearableRules,
  ...vehicleRules,
  ...extraRules,
  ...iotRules,

  // EMBEDDED

  [/(aeobc)\b/i],
  [MODEL, [VENDOR, AMAZON], [TYPE, EMBEDDED]],

  [/(homepod).+mac os/i],
  [MODEL, [VENDOR, APPLE], [TYPE, EMBEDDED]],

  [/windows iot/i],
  [[TYPE, EMBEDDED]],

  // GENERIC FALLBACKS

  [/\b((4k|android|smart|opera)[- ]?tv|tv; rv:|large screen[\w ]+safari)\b/i],
  [[TYPE, SMARTTV]],

  [/droid .+?; ([^;]+?)(?: bui|; wv\)|\) applew).+?(mobile|vr|\d) safari/i],
  [
    MODEL,
    [
      TYPE,
      v => {
        const l = lower(v);
        if (l === 'mobile') {
          return MOBILE;
        }
        if (l === 'vr') {
          return XR;
        }
        return TABLET;
      },
    ],
  ],

  [/\b((tablet|tab)[;/]|focus\/\d(?!.+mobile))/i],
  [[TYPE, TABLET]],

  [/(phone|mobile(?:[;/]| [\w/.]*safari)|pda(?=.+windows ce))/i],
  [[TYPE, MOBILE]],

  [/droid .+?; ([\w. -]+)( bui|\))/i],
  [MODEL, [VENDOR, 'Generic']],
];
