import { ARCHITECTURE } from '../constants.js';
import { lower } from '../helpers.js';

export const cpuRules = [
  [/\b((amd|x|x86[-_]?|wow|win)64)\b/i],
  [[ARCHITECTURE, 'amd64']],

  [/(ia32(?=;))/i, /\b((i[346]|x)86)(pc)?\b/i],
  [[ARCHITECTURE, 'ia32']],

  [/\b(aarch64|arm(v?[89]e?l?|_?64))\b/i],
  [[ARCHITECTURE, 'arm64']],

  [/\b(arm(v[67])?ht?n?[fl]p?)\b/i],
  [[ARCHITECTURE, 'armhf']],

  [/( (ce|mobile); ppc;|\/[\w.]+arm\b)/i],
  [[ARCHITECTURE, 'arm']],

  [/ sun4\w[;)]/i],
  [[ARCHITECTURE, 'sparc']],

  [
    /\b(avr32|ia64(?=;)|68k(?=\))|\barm(?=v([1-7]|[5-7]1)l?|;|eabi)|(irix|mips|sparc)(64)?\b|pa-risc)/i,
    /((ppc|powerpc)(64)?)( mac|;|\))/i,
    /(?:osf1|[freopnt]{3,4}bsd) (alpha)/i,
  ],
  [[ARCHITECTURE, v => lower(v.replace(/ower/, ''))]],

  [/mc680.0/i],
  [[ARCHITECTURE, '68k']],

  [/winnt.+\[axp/i],
  [[ARCHITECTURE, 'alpha']],
];
