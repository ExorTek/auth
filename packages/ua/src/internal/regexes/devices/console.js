import { MODEL, VENDOR, TYPE, CONSOLE, SONY, MICROSOFT, VALVE } from '../../constants.js';

export const consoleRules = [
  [/(playstation \w+)/i],
  [MODEL, [VENDOR, SONY], [TYPE, CONSOLE]],

  [/\b(xbox(?: one| series [xs])?(?!; xbox))[\); ]/i],
  [MODEL, [VENDOR, MICROSOFT], [TYPE, CONSOLE]],

  [/(nintendo) (\w+)/i],
  [VENDOR, MODEL, [TYPE, CONSOLE]],

  [/valve steam deck/i, /steam deck/i],
  [
    [VENDOR, VALVE],
    [MODEL, 'Steam Deck'],
    [TYPE, CONSOLE],
  ],

  [/\b(ouya)\b/i],
  [MODEL, [VENDOR, 'Ouya'], [TYPE, CONSOLE]],

  [/atari ?vcs/i],
  [
    [VENDOR, 'Atari'],
    [MODEL, 'VCS'],
    [TYPE, CONSOLE],
  ],

  [/steamoverlay/i, /valve steam gameoverlay/i],
  [
    [VENDOR, VALVE],
    [MODEL, 'Steam'],
    [TYPE, CONSOLE],
  ],
];
