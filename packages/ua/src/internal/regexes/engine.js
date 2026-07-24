import { NAME, VERSION } from '../constants.js';

export const engineRules = [
  [/windows.+ edge\/([\w.]+)/i],
  [VERSION, [NAME, 'EdgeHTML']],

  [/(arkweb)\/([\w.]+)/i],
  [NAME, VERSION],

  [/webkit\/537\.36.+chrome\/(?!27)([\w.]+)/i],
  [VERSION, [NAME, 'Blink']],

  [
    /(presto)\/([\w.]+)/i,
    /(webkit|trident|netfront|netsurf|amaya|lynx|w3m|goanna|servo)\/([\w.]+)/i,
    /ekioh(flow)\/([\w.]+)/i,
    /(khtml|tasman|links|dillo)[\/ ]\(?([\w.]+)/i,
    /(icab)[\/ ]([23]\.[\d.]+)/i,
    /\b(libweb)/i,
  ],
  [NAME, VERSION],

  [/ladybird\//i],
  [[NAME, 'LibWeb']],

  [/rv:([\w.]{1,9})\b.+(gecko)/i],
  [VERSION, NAME],
];
