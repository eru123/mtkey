/** The Encoding methods: Base64, Base32, Base58, Hex, URL, Binary, Morse.
 * Ported from the C# Methods_Encoding with the explainer copy intact. */
import {
  CipherError,
  defineMethod,
  type CipherMethod,
  type CipherRequest,
} from './types'
import {
  base64,
  base32,
  base58,
  unbase64,
  unbase32,
  unbase58,
  hex,
  unhex,
  utf8Encode,
  utf8Decode,
  toBinary,
  fromBinary,
} from './primitives'

function inputBytes(r: CipherRequest): Uint8Array {
  return utf8Encode(r.input)
}

/** RFC 3986 strict percent-encoding, matching .NET's Uri.EscapeDataString:
 * everything outside ALPHA / DIGIT / "-" / "." / "_" / "~" is escaped. */
export function percentEncode(text: string): string {
  return encodeURIComponent(text).replace(
    /[!'()*]/g,
    (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase()
  )
}

/** Lenient decode in the .NET Uri.UnescapeDataString style: malformed
 * escapes pass through untouched instead of throwing. */
export function percentDecode(text: string): string {
  let out = ''
  for (let i = 0; i < text.length; i++) {
    if (
      text[i] === '%' &&
      i + 2 < text.length + 1 &&
      /^[0-9a-fA-F]{2}$/.test(text.substring(i + 1, i + 3))
    ) {
      out += String.fromCharCode(parseInt(text.substring(i + 1, i + 3), 16))
      i += 2
    } else {
      out += text[i]
    }
  }
  // Multi-byte sequences were decoded per byte; reassemble through UTF-8.
  const bytes = new Uint8Array(out.length)
  for (let i = 0; i < out.length; i++) bytes[i] = out.charCodeAt(i) & 0xff
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes)
  } catch {
    return out
  }
}

export const base64Method: CipherMethod = defineMethod({
  id: 'base64',
  name: 'Base64',
  category: 'Encoding',
  blurb: 'Wraps binary data in 64 safe alphabet characters.',
  learn:
    'Base64 turns any bytes into letters, digits, + and / so they can travel through ' +
    'systems that only understand text (email, JSON, URLs). Every 3 bytes become 4 ' +
    'characters, which is why encoded data is about a third bigger. It hides nothing: ' +
    'anyone can reverse it, it is an encoding, not encryption.',
  wikiUrl: 'https://en.wikipedia.org/wiki/Base64',
  aliases: ['b64'],
  process: async (r) =>
    r.direction === 'encode'
      ? { output: base64(inputBytes(r)) }
      : { output: utf8Decode(unbase64(r.input)) },
})

export const base32Method: CipherMethod = defineMethod({
  id: 'base32',
  name: 'Base32',
  category: 'Encoding',
  blurb: 'Same idea as Base64 but case-insensitive, A-Z and 2-7.',
  learn:
    'Base32 uses 32 characters, all upper-case letters and the digits 2 to 7, so it ' +
    'survives being read out loud, printed without case, or punched into a hardware ' +
    'token. TOTP authenticator secrets are usually Base32 for exactly this reason.',
  wikiUrl: 'https://en.wikipedia.org/wiki/Base32',
  process: async (r) =>
    r.direction === 'encode'
      ? { output: base32(inputBytes(r)) }
      : { output: utf8Decode(unbase32(r.input)) },
})

export const base58Method: CipherMethod = defineMethod({
  id: 'base58',
  name: 'Base58',
  category: 'Encoding',
  blurb: "Bitcoin's alphabet: no 0, O, I or l, safe to read and dictate.",
  learn:
    'Base58 drops the characters people misread (zero, capital O, capital I, lowercase L) ' +
    'from the Base64 alphabet. Bitcoin addresses, IPFS hashes and private key WIF strings ' +
    'use it. There is no padding and no + or /, so it also survives double-click selection.',
  wikiUrl: 'https://en.wikipedia.org/wiki/Base58',
  process: async (r) =>
    r.direction === 'encode'
      ? { output: base58(inputBytes(r)) }
      : { output: utf8Decode(unbase58(r.input)) },
})

export const hexMethod: CipherMethod = defineMethod({
  id: 'hex',
  name: 'Hexadecimal',
  category: 'Encoding',
  blurb: 'Every byte as two hex digits, the classic dump format.',
  learn:
    "Hex maps each byte to two characters from 0-9 and a-f. It is the native language of " +
    "debuggers, cryptographic output and packet captures because you can see every single " +
    "bit position. 41 is 'A' in ASCII, 0x41 in hex, 01000001 in binary.",
  wikiUrl: 'https://en.wikipedia.org/wiki/Hexadecimal',
  aliases: ['base16'],
  process: async (r) =>
    r.direction === 'encode'
      ? { output: hex(inputBytes(r)) }
      : { output: utf8Decode(unhex(r.input)) },
})

export const urlMethod: CipherMethod = defineMethod({
  id: 'url',
  name: 'URL Encoding',
  category: 'Encoding',
  blurb: 'Percent-encoding for text that travels inside a URL.',
  learn:
    "URLs may only carry a limited set of characters, so anything else gets replaced with " +
    "a percent sign followed by the byte's hex value. A space becomes %20, an emoji becomes " +
    'four byte escapes. Note that a plus sign is NOT a space in strict RFC 3986 encoding, ' +
    'that habit comes from old HTML form encoding.',
  wikiUrl: 'https://en.wikipedia.org/wiki/Percent-encoding',
  aliases: ['percent', 'uri'],
  process: async (r) =>
    r.direction === 'encode'
      ? { output: percentEncode(r.input) }
      : { output: percentDecode(r.input) },
})

export const binaryMethod: CipherMethod = defineMethod({
  id: 'binary',
  name: 'Binary (text to bits)',
  category: 'Encoding',
  blurb: 'Turns text into raw 0s and 1s, one byte at a time.',
  learn:
    'This shows what the computer actually stores: each character becomes its byte value, ' +
    'each byte eight bits. ' +
    "'Hi' is 72 and 105 in decimal, 01001000 and 01101001 in binary. " +
    'UTF-8 text with accents or emoji needs more than one byte per character, and you will ' +
    'see exactly where the bytes split.',
  wikiUrl: 'https://en.wikipedia.org/wiki/Binary-to-text_encoding',
  process: async (r) =>
    r.direction === 'encode'
      ? { output: toBinary(inputBytes(r)) }
      : { output: utf8Decode(fromBinary(r.input)) },
})

const MORSE_TABLE: Record<string, string> = {
  a: '.-', b: '-...', c: '-.-.', d: '-..',
  e: '.', f: '..-.', g: '--.', h: '....',
  i: '..', j: '.---', k: '-.-', l: '.-..',
  m: '--', n: '-.', o: '---', p: '.--.',
  q: '--.-', r: '.-.', s: '...', t: '-',
  u: '..-', v: '...-', w: '.--', x: '-..-',
  y: '-.--', z: '--..',
  '0': '-----', '1': '.----', '2': '..---', '3': '...--',
  '4': '....-', '5': '.....', '6': '-....', '7': '--...',
  '8': '---..', '9': '----.',
  '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.',
  '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-',
  '&': '.-...', ':': '---...', ';': '-.-.-.', '=': '-...-',
  '+': '.-.-.', '-': '-....-', '"': '.-..-.', '@': '.--.-.',
  _: '..--.-',
}

const MORSE_REVERSE: Record<string, string> = {}
for (const [ch, code] of Object.entries(MORSE_TABLE)) MORSE_REVERSE[code] = ch

export const morseMethod: CipherMethod = defineMethod({
  id: 'morse',
  name: 'Morse Code',
  category: 'Encoding',
  blurb: 'Dots and dashes, the original digital encoding.',
  learn:
    'Morse code from the 1840s encodes each letter as short and long signals. In written ' +
    'form, letters are separated by spaces and words by a slash. It is a variable-length ' +
    'code designed so the most common English letters (E, T) get the shortest symbols, ' +
    'an idea that later inspired Huffman coding.',
  wikiUrl: 'https://en.wikipedia.org/wiki/Morse_code',
  process: async (r) => {
    if (r.direction === 'encode') {
      let out = ''
      for (const word of r.input.split(' ').filter((w) => w.length > 0)) {
        if (out.length > 0) out += ' / '
        for (const ch of word) {
          const code = MORSE_TABLE[ch.toLowerCase()]
          if (!code) throw new CipherError(`Morse has no symbol for '${ch}'.`)
          out += code + ' '
        }
      }
      return { output: out.trimEnd() }
    }

    let out = ''
    for (const word of r.input.replace(/\n/g, ' ').split(/ \/ |\//)) {
      for (const letter of word.split(' ').filter((l) => l.length > 0)) {
        const ch = MORSE_REVERSE[letter]
        if (!ch) throw new CipherError(`Unknown Morse sequence '${letter}'.`)
        out += ch
      }
      out += ' '
    }
    return { output: out.trimEnd() }
  },
})

export const encodingMethods: readonly CipherMethod[] = [
  base64Method,
  base32Method,
  base58Method,
  hexMethod,
  urlMethod,
  binaryMethod,
  morseMethod,
]
