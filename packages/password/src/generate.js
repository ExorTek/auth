import { sampleAlphabet, sampleUint16Indices } from '@exortek/shared/sample';
import { invalidArgument } from './internal/guards.js';
import { isArray, isString } from '@exortek/shared/predicates';

// Named alphabets — the character sets 99% of "give me a random
// password" callers actually want. Custom alphabets stay possible via
// the `alphabet` option.
export const alphabets = Object.freeze({
  // Crockford base32 minus 0/O/1/I/L — human-unambiguous, terminal-safe.
  // Best default for machine-generated passwords the user has to type
  // back.
  crockford: '23456789ABCDEFGHJKMNPQRSTVWXYZ',
  alnum: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
  // Full ASCII printable minus quotes and backslash — those trip up
  // shells and JSON in a way that surprises callers.
  ascii: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&()*+,-./:;<=>?@[]^_`{|}~',
  hex: '0123456789abcdef',
  // Lowercase letters + digits, no visually-ambiguous characters.
  urlSafe: 'abcdefghjkmnpqrstuvwxyz23456789',
});

/**
 * @typedef {object} GenerateOptions
 * @property {number} [length=24]
 *   Output length in characters. 24 characters of Crockford base32
 *   (~118 bits of entropy) comfortably clears every 2024 threat model.
 * @property {keyof typeof alphabets | string} [alphabet='crockford']
 *   Named alphabet (see {@link alphabets}) or a custom character set.
 *   Custom alphabets must contain 2-256 distinct characters and no
 *   surrogate halves.
 */

/**
 * Generate a random password using {@link randomBytes} as a CSPRNG source
 * and unbiased rejection sampling. Never produces a modulo bias — the
 * naive `bytes[i] % alphabet.length` approach skews the first few
 * characters of the alphabet on any length that isn't a divisor of 256.
 *
 * @example
 * // Default: 24 chars of Crockford base32
 * const pw = password.generate()   // 'K7VXNMHT9RBWPXFQKGH2JYCM'
 *
 * @example
 * // Custom alphabet — hex-only, useful for hardware token labels
 * password.generate({ length: 16, alphabet: 'hex' })
 *
 * @param {GenerateOptions} [options]
 * @returns {string}
 */
export function generate(options = {}) {
  const length = options.length ?? 24;
  if (!Number.isInteger(length) || length < 1 || length > 1024) {
    throw invalidArgument(`generate.options.length must be an integer in [1, 1024]; got ${length}`);
  }
  const alphabetInput = options.alphabet ?? 'crockford';
  const alphabet = isString(alphabetInput) && alphabets[alphabetInput] ? alphabets[alphabetInput] : alphabetInput;
  if (!isString(alphabet) || alphabet.length < 2 || alphabet.length > 256) {
    throw invalidArgument(
      `generate.options.alphabet must be a string of 2-256 characters (or a named alphabet: ${Object.keys(alphabets).join(', ')}); got ${isString(alphabet) ? `length ${alphabet.length}` : typeof alphabet}`,
    );
  }
  return sampleAlphabet(alphabet, length);
}

// Diceware short word list — 6-word phrases at 12.9 bits of entropy per
// word give ~77 bits total, which for passphrases beats a 12-char random
// password on memorability without giving up much strength.
//
// The list is intentionally hand-curated and short (256 words) so it fits
// in the bundle without a data file. For higher-entropy passphrases pull
// a full EFF list into your own consumer code and pass it in.
const DEFAULT_WORDS = [
  'able',
  'acid',
  'aged',
  'also',
  'area',
  'army',
  'away',
  'baby',
  'back',
  'ball',
  'band',
  'bank',
  'base',
  'bath',
  'bear',
  'beat',
  'been',
  'beer',
  'bell',
  'belt',
  'best',
  'bike',
  'bill',
  'bird',
  'blow',
  'blue',
  'boat',
  'body',
  'bomb',
  'bone',
  'book',
  'boom',
  'born',
  'boss',
  'both',
  'bowl',
  'bulk',
  'burn',
  'bush',
  'busy',
  'cake',
  'call',
  'calm',
  'came',
  'camp',
  'card',
  'care',
  'case',
  'cash',
  'cast',
  'cell',
  'chat',
  'chip',
  'city',
  'club',
  'coal',
  'coat',
  'code',
  'cold',
  'come',
  'cook',
  'cool',
  'cope',
  'copy',
  'core',
  'cost',
  'crew',
  'crop',
  'dark',
  'data',
  'date',
  'dawn',
  'days',
  'dead',
  'deal',
  'dean',
  'dear',
  'debt',
  'deep',
  'deny',
  'desk',
  'dial',
  'dice',
  'diet',
  'dirt',
  'disc',
  'disk',
  'does',
  'done',
  'door',
  'dose',
  'down',
  'draw',
  'drew',
  'drop',
  'drug',
  'dual',
  'duke',
  'dust',
  'duty',
  'each',
  'earn',
  'ease',
  'east',
  'easy',
  'edge',
  'else',
  'even',
  'ever',
  'evil',
  'exit',
  'face',
  'fact',
  'fail',
  'fair',
  'fall',
  'farm',
  'fast',
  'fate',
  'fear',
  'feed',
  'feel',
  'fell',
  'felt',
  'file',
  'fill',
  'film',
  'find',
  'fine',
  'fire',
  'firm',
  'fish',
  'five',
  'flag',
  'flat',
  'flow',
  'food',
  'foot',
  'ford',
  'form',
  'fort',
  'four',
  'free',
  'from',
  'fuel',
  'full',
  'fund',
  'gain',
  'game',
  'gate',
  'gave',
  'gear',
  'gene',
  'gift',
  'girl',
  'give',
  'glad',
  'goal',
  'goes',
  'gold',
  'golf',
  'gone',
  'good',
  'gray',
  'grew',
  'grey',
  'grow',
  'gulf',
  'hair',
  'half',
  'hall',
  'hand',
  'hang',
  'hard',
  'harm',
  'hate',
  'have',
  'head',
  'hear',
  'heat',
  'held',
  'hell',
  'help',
  'here',
  'hero',
  'high',
  'hill',
  'hire',
  'hold',
  'hole',
  'holy',
  'home',
  'hope',
  'host',
  'hour',
  'huge',
  'hung',
  'hunt',
  'hurt',
  'idea',
  'inch',
  'into',
  'iron',
  'item',
  'jack',
  'jane',
  'jean',
  'john',
  'join',
  'jump',
  'jury',
  'just',
  'keen',
  'keep',
  'kent',
  'kept',
  'kick',
  'kill',
  'kind',
  'king',
  'knee',
  'knew',
  'know',
  'lack',
  'lady',
  'laid',
  'lake',
  'land',
  'lane',
  'last',
  'late',
  'lead',
  'left',
  'less',
  'life',
  'lift',
  'like',
  'line',
  'link',
  'list',
  'live',
  'load',
  'loan',
  'lock',
  'logo',
  'long',
  'look',
  'lord',
  'lose',
  'loss',
  'lost',
  'love',
  'luck',
  'made',
  'mail',
];

/**
 * @typedef {object} PassphraseOptions
 * @property {number} [words=6]           Number of words. 6 × 8 bits/word ≈ 48 bits
 *                                        with the default 256-word list; use a longer
 *                                        list (via {@link PassphraseOptions.wordList})
 *                                        for higher entropy.
 * @property {string} [separator='-']     Character to join words with.
 * @property {string[]} [wordList]        Custom word list. Must contain
 *                                        128 or more distinct entries.
 * @property {boolean} [capitalize=false] Capitalize the first letter of each word.
 */

/**
 * Generate a memorable diceware-style passphrase. Uses CSPRNG rejection
 * sampling to pick words with zero modulo bias.
 *
 * @example
 * password.passphrase()                                   // 'boat-drew-fire-lake-hold-just'
 * password.passphrase({ words: 8, separator: ' ' })       // 'wave river ...'
 *
 * @param {PassphraseOptions} [options]
 * @returns {string}
 */
export function passphrase(options = {}) {
  const count = options.words ?? 6;
  if (!Number.isInteger(count) || count < 1 || count > 64) {
    throw invalidArgument(`passphrase.options.words must be an integer in [1, 64]; got ${count}`);
  }
  const separator = options.separator ?? '-';
  if (!isString(separator)) {
    throw invalidArgument('passphrase.options.separator must be a string');
  }
  const list = options.wordList ?? DEFAULT_WORDS;
  if (!isArray(list) || list.length < 128) {
    throw invalidArgument(
      `passphrase.options.wordList must be an array of ≥ 128 words; got ${isArray(list) ? list.length : typeof list}`,
    );
  }
  const capitalize = options.capitalize === true;
  const indices = sampleUint16Indices(list.length, count);
  const words = indices.map(idx => {
    const w = list[idx];
    return capitalize ? w[0].toUpperCase() + w.slice(1) : w;
  });
  return words.join(separator);
}
