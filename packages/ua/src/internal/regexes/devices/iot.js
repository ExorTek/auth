import {
  MODEL,
  VENDOR,
  TYPE,
  SMART_SPEAKER,
  SMART_DISPLAY,
  CAMERA,
  PORTABLE_MEDIA_PLAYER,
  AMAZON,
  APPLE,
  GOOGLE,
  MICROSOFT,
} from '../../constants.js';

// SMART SPEAKERS
export const smartSpeakerRules = [
  [/\b(echo)(?!.*show)(?!.*spot).+alexa/i],
  [MODEL, [VENDOR, AMAZON], [TYPE, SMART_SPEAKER]],

  [/(google home|google nest mini|google nest audio)/i],
  [MODEL, [VENDOR, GOOGLE], [TYPE, SMART_SPEAKER]],

  [/(homepod mini).+mac os/i],
  [MODEL, [VENDOR, APPLE], [TYPE, SMART_SPEAKER]],
];

// SMART DISPLAYS
export const smartDisplayRules = [
  [/(echo show|echo spot)\b/i],
  [MODEL, [VENDOR, AMAZON], [TYPE, SMART_DISPLAY]],

  [/(google nest hub(?:\s+max)?)\b/i],
  [MODEL, [VENDOR, GOOGLE], [TYPE, SMART_DISPLAY]],

  [/(facebook portal(?:\s+\w+)?)\b/i],
  [MODEL, [VENDOR, 'Meta'], [TYPE, SMART_DISPLAY]],
];

// CAMERAS
export const cameraRules = [[/(nikon|canon|gopro|sony) (?:d\d{3,4}|eos|hero|alpha)/i], [VENDOR, [TYPE, CAMERA]]];

// PORTABLE MEDIA PLAYERS
export const mediaPlayerRules = [
  [/(?:\/|\()(ipod[\w, ]*)[/);]/i],
  [MODEL, [VENDOR, APPLE], [TYPE, PORTABLE_MEDIA_PLAYER]],

  [/(zune)\b/i],
  [MODEL, [VENDOR, MICROSOFT], [TYPE, PORTABLE_MEDIA_PLAYER]],
];

export const iotRules = [...smartSpeakerRules, ...smartDisplayRules, ...cameraRules, ...mediaPlayerRules];
