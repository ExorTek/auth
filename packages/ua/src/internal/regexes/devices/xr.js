import {
  MODEL,
  VENDOR,
  TYPE,
  XR,
  GOOGLE,
  FACEBOOK,
  APPLE,
  MICROSOFT,
  SONY,
  SAMSUNG,
  VALVE,
  HTC,
} from '../../constants.js';

export const xrRules = [
  [/droid.+; (glass) \d/i],
  [MODEL, [VENDOR, GOOGLE], [TYPE, XR]],

  [/(pico) ([\w ]+) os\d/i],
  [VENDOR, MODEL, [TYPE, XR]],

  [/(quest( \d| pro)?s?).+vr/i],
  [MODEL, [VENDOR, FACEBOOK], [TYPE, XR]],

  [/apple vision pro/i],
  [
    [MODEL, 'Vision Pro'],
    [VENDOR, APPLE],
    [TYPE, XR],
  ],

  [/(hololens)(?:\s*\d)?/i],
  [MODEL, [VENDOR, MICROSOFT], [TYPE, XR]],

  [/(vive) (focus|flow|cosmos|pro|xr elite)[\s);/]/i, /(vive)\b/i],
  [[VENDOR, HTC], MODEL, [TYPE, XR]],

  [/magic leap (one|two|\d)/i, /magic.?leap/i],
  [[VENDOR, 'Magic Leap'], MODEL, [TYPE, XR]],

  [/valve (index)/i],
  [[VENDOR, VALVE], MODEL, [TYPE, XR]],

  [/playstation vr(\d)?/i],
  [
    [MODEL, 'PlayStation VR'],
    [VENDOR, SONY],
    [TYPE, XR],
  ],

  [/\b(gear vr)\b/i],
  [MODEL, [VENDOR, SAMSUNG], [TYPE, XR]],

  [/\b(xreal) (air|beam|light)\b/i],
  [VENDOR, MODEL, [TYPE, XR]],

  [/(varjo) (aero|xr-[34])/i],
  [VENDOR, MODEL, [TYPE, XR]],

  [/(pimax) ([\w ]+)/i],
  [VENDOR, MODEL, [TYPE, XR]],

  [/hp (reverb[\w ]*)/i],
  [[VENDOR, 'HP'], MODEL, [TYPE, XR]],

  [/(lynx)-r1/i],
  [VENDOR, [MODEL, 'R-1'], [TYPE, XR]],

  [/\b(bigscreen) beyond/i],
  [VENDOR, [MODEL, 'Beyond'], [TYPE, XR]],
];
