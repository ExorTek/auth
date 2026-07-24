import { VENDOR, MODEL, TYPE, VEHICLE } from '../../constants.js';

export const vehicleRules = [
  [/aftlbt962e2/i],
  [
    [VENDOR, 'BMW'],
    [TYPE, VEHICLE],
  ],

  [/dilink.+(byd) auto/i],
  [VENDOR, [TYPE, VEHICLE]],

  [/aftlft962x3/i],
  [
    [VENDOR, 'Jeep'],
    [MODEL, 'Wagoneer'],
    [TYPE, VEHICLE],
  ],

  [/(rivian) (r1[ts])/i],
  [VENDOR, MODEL, [TYPE, VEHICLE]],

  [/vcc.+netfront/i],
  [
    [VENDOR, 'Volvo'],
    [TYPE, VEHICLE],
  ],

  [/(tesla)(?: qtcarbrowser|\/[\w.-]+)/i],
  [VENDOR, [TYPE, VEHICLE]],

  [/mercedes[- ]?benz.+(?:mbux|browser)/i, /mbux/i],
  [
    [VENDOR, 'Mercedes-Benz'],
    [TYPE, VEHICLE],
  ],

  [/audi.+(?:mmi|browser)/i],
  [
    [VENDOR, 'Audi'],
    [TYPE, VEHICLE],
  ],

  [/ford.+(?:sync|browser)/i],
  [
    [VENDOR, 'Ford'],
    [TYPE, VEHICLE],
  ],

  [/gm.+(?:infotainment|mylink)/i, /chevrolet.+(?:infotainment|mylink)/i],
  [
    [VENDOR, 'GM'],
    [TYPE, VEHICLE],
  ],

  [/hyundai.+(?:bluelink|browser)/i],
  [
    [VENDOR, 'Hyundai'],
    [TYPE, VEHICLE],
  ],

  [/kia.+(?:uvo|browser)/i],
  [
    [VENDOR, 'Kia'],
    [TYPE, VEHICLE],
  ],

  [/polestar/i],
  [
    [VENDOR, 'Polestar'],
    [TYPE, VEHICLE],
  ],

  [/lucid.+browser/i],
  [
    [VENDOR, 'Lucid'],
    [TYPE, VEHICLE],
  ],

  [/nio.+browser/i],
  [
    [VENDOR, 'NIO'],
    [TYPE, VEHICLE],
  ],

  [/toyota.+(?:entune|browser)/i],
  [
    [VENDOR, 'Toyota'],
    [TYPE, VEHICLE],
  ],
];
