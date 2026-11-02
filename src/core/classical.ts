/** The Classical methods: Caesar, ROT13, Atbash, Vigenère, Rail Fence,
 * XOR and Playfair. Ported from the C# Methods_Classical with the
 * explainer copy intact. All of them walk UTF-16 code units, exactly like
 * the C# char loops did. */
import {
  CipherError,
  defineMethod,
  field,
  type CipherMethod,} from './types'
import { hex, unhex, utf8Encode, utf8Decode } from './primitives'

export const caesarMethod: CipherMethod = defineMethod({
  id: 'caesar',
  name: 'Caesar Cipher',
  category: 'Classical',
  blurb: 'Shift every letter along the alphabet by a fixed amount.',
  learn:
    'Julius Caesar reportedly shifted letters by 3 to hide messages. Each letter moves a ' +
    'fixed number of places along the alphabet and wraps around, so with shift 3, CAT ' +
    'becomes FDW. There are only 25 possible shifts, which is why you can break it by ' +
    'trying them all, a technique called brute force.',
  wikiUrl: 'https://en.wikipedia.org/wiki/Caesar_cipher',
  fields: [
    {
      name: 'shift',
      label: 'Shift',
      kind: 'number',
      default: '3',
      min: 0,
      max: 25,
      hint: 'How many letters to slide (0-25). Try 3 for the classic Caesar.',
      generator: 'number',
      generatorRange: [1, 25],
    },
  ],
  process: async (r) => {
    const shift = parseShift(field(r, 'shift'))
    const effective = r.direction === 'encode' ? shift : 26 - shift
    return { output: shiftLetters(r.input, effective) }
  },
})

function parseShift(text: string): number {
  const shift = Number.parseInt(text.trim(), 10)
  if (Number.isNaN(shift) || shift < 0 || shift > 25)
    throw new CipherError('Shift must be a number from 0 to 25.')
  return shift
}

function shiftLetters(text: string, shift: number): string {
  let out = ''
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i)
    if (c >= 65 && c <= 90) out += String.fromCharCode(65 + ((c - 65 + shift) % 26))
    else if (c >= 97 && c <= 122) out += String.fromCharCode(97 + ((c - 97 + shift) % 26))
    else out += text[i]
  }
  return out
}

export const rot13Method: CipherMethod = defineMethod({
  id: 'rot13',
  name: 'ROT13',
  category: 'Classical',
  blurb: 'Caesar with shift 13. Applying it twice brings the text back.',
  learn:
    'ROT13 shifts letters by 13, exactly half the alphabet, so encoding and decoding are ' +
    'the same operation. Usenet forums used it to hide spoilers and punchlines: the reader ' +
    'who wants the spoiler runs the text through ROT13, everyone else skips it. It is a ' +
    'prime example of obfuscation, not security.',
  wikiUrl: 'https://en.wikipedia.org/wiki/ROT13',
  process: async (r) => ({ output: shiftLetters(r.input, 13) }),
})

export const atbashMethod: CipherMethod = defineMethod({
  id: 'atbash',
  name: 'Atbash',
  category: 'Classical',
  blurb: 'Mirrors the alphabet: A becomes Z, B becomes Y, and so on.',
  learn:
    'Atbash reverses the alphabet, mapping A to Z and B to Y. It appears in the Hebrew ' +
    'Book of Jeremiah from the 6th century BC, making it one of the oldest ciphers we ' +
    'know of. Like ROT13 it is its own inverse, and like every classical cipher it offers ' +
    'zero real security today.',
  wikiUrl: 'https://en.wikipedia.org/wiki/Atbash',
  process: async (r) => {
    let out = ''
    for (let i = 0; i < r.input.length; i++) {
      const c = r.input.charCodeAt(i)
      if (c >= 65 && c <= 90) out += String.fromCharCode(90 - (c - 65))
      else if (c >= 97 && c <= 122) out += String.fromCharCode(122 - (c - 97))
      else out += r.input[i]
    }
    return { output: out }
  },
})

export const vigenereMethod: CipherMethod = defineMethod({
  id: 'vigenere',
  name: 'Vigenère Cipher',
  category: 'Classical',
  blurb: 'A rolling Caesar: each letter shifts by the next letter of a keyword.',
  learn:
    'The Vigenère cipher uses a keyword as a table of shifts: the first plaintext letter ' +
    "moves by the keyword's first letter, the second by the second, looping the keyword " +
    'as needed. For 300 years it was called le chiffre indéchiffrable until Kasiski and ' +
    'Babbage showed that repeated keywords leak the key length through repeated patterns.',
  wikiUrl: 'https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher',
  aliases: ['vigenere'],
  fields: [
    {
      name: 'key',
      label: 'Keyword',
      placeholder: 'SECRET',
      hint: 'Only letters count. A longer keyword means a stronger shift pattern.',
      generator: 'password',
      generatorSize: 8,
    },
  ],
  process: async (r) => {
    const key = Array.from(field(r, 'key'))
      .filter((c) => /[a-zA-Z]/.test(c))
      .map((c) => c.toLowerCase())
    if (key.length === 0) throw new CipherError('The keyword needs at least one letter.')
    const sign = r.direction === 'encode' ? 1 : -1

    let out = ''
    let ki = 0
    for (let i = 0; i < r.input.length; i++) {
      const c = r.input.charCodeAt(i)
      if (c >= 65 && c <= 90) {
        out += String.fromCharCode(65 + mod(c - 65 + sign * (key[ki].charCodeAt(0) - 97), 26))
        ki = (ki + 1) % key.length
      } else if (c >= 97 && c <= 122) {
        out += String.fromCharCode(97 + mod(c - 97 + sign * (key[ki].charCodeAt(0) - 97), 26))
        ki = (ki + 1) % key.length
      } else {
        out += r.input[i]
      }
    }
    return { output: out }
  },
})

function mod(v: number, m: number): number {
  return ((v % m) + m) % m
}

export const railFenceMethod: CipherMethod = defineMethod({
  id: 'railfence',
  name: 'Rail Fence',
  category: 'Classical',
  blurb: 'Writes text in a zigzag across N rails, reads it row by row.',
  learn:
    'A transposition cipher: the letters never change, only their order does. You write ' +
    'the message diagonally up and down across a number of rails, then read each rail ' +
    'left to right. WEAREDISCOVERED on 3 rails becomes WECRLTEERDSOEE. Transposition ' +
    'pairs naturally with substitution ciphers, stacking both is how Enigma-era systems ' +
    'were built.',
  wikiUrl: 'https://en.wikipedia.org/wiki/Rail_fence_cipher',
  aliases: ['zigzag'],
  fields: [
    {
      name: 'rails',
      label: 'Rails',
      kind: 'number',
      default: '3',
      min: 2,
      max: 20,
      hint: 'Number of zigzag rows. Both sides need the same count.',
      generator: 'number',
      generatorRange: [2, 8],
    },
  ],
  process: async (r) => {
    const rails = Number.parseInt(field(r, 'rails').trim(), 10)
    if (Number.isNaN(rails) || rails < 2 || rails > 20)
      throw new CipherError('Rails must be a number from 2 to 20.')
    const text = r.input
    if (text.length === 0) return { output: '' }

    const pattern = zigzag(text.length, rails)
    if (r.direction === 'encode') {
      let out = ''
      for (let rail = 0; rail < rails; rail++)
        for (let i = 0; i < text.length; i++) if (pattern[i] === rail) out += text[i]
      return { output: out }
    }
    const result = new Array<string>(text.length)
    let source = 0
    for (let rail = 0; rail < rails; rail++)
      for (let i = 0; i < text.length; i++) if (pattern[i] === rail) result[i] = text[source++]
    return { output: result.join('') }
  },
})

function zigzag(length: number, rails: number): number[] {
  const pattern = new Array<number>(length)
  let rail = 0
  let step = 1
  for (let i = 0; i < length; i++) {
    pattern[i] = rail
    if (rail === 0) step = 1
    else if (rail === rails - 1) step = -1
    rail += step
  }
  return pattern
}

export const xorMethod: CipherMethod = defineMethod({
  id: 'xor',
  name: 'XOR Cipher',
  category: 'Classical',
  blurb: 'XORs every byte with a repeating key. Output arrives as hex.',
  learn:
    'XOR is the atom of cryptography: a bit flipped twice comes back, so the same ' +
    'operation encrypts and decrypts. One-Time Pads (a random key as long as the message) ' +
    'are provably unbreakable this way. Repeating a short key instead is the Vigenère ' +
    'mistake all over again, and that is what cracks messages like the Enigma-era ' +
    'diplomatic cables.',
  wikiUrl: 'https://en.wikipedia.org/wiki/XOR_cipher',
  encodeLabel: 'Encode to hex',
  decodeLabel: 'Decode from hex',
  fields: [
    {
      name: 'key',
      label: 'Key',
      placeholder: 'secret',
      hint: 'Repeated over the message. Encode reads the key as text, one letter per byte.',
      generator: 'password',
      generatorSize: 16,
    },
  ],
  process: async (r) => {
    const key = utf8Encode(field(r, 'key'))
    if (key.length === 0) throw new CipherError('XOR needs a key.')
    if (r.direction === 'encode') {
      return { output: hex(xorBytes(utf8Encode(r.input), key)) }
    }
    return { output: utf8Decode(xorBytes(unhex(r.input), key)) }
  },
})

function xorBytes(data: Uint8Array, key: Uint8Array): Uint8Array {
  const output = new Uint8Array(data.length)
  for (let i = 0; i < data.length; i++) output[i] = data[i] ^ key[i % key.length]
  return output
}

export const playfairMethod: CipherMethod = defineMethod({
  id: 'playfair',
  name: 'Playfair Cipher',
  category: 'Classical',
  blurb: 'Digraph cipher from a 5x5 keyword square, I and J share a cell.',
  learn:
    'Playfair encrypts letter PAIRS using a 5x5 square built from a keyword (I and J ' +
    'share one cell). Same-row letters shift right, same-column letters shift down, and ' +
    'corner letters swap horizontally. Double letters get an X between them and an odd ' +
    'tail gets an X appended, so decryption cannot always undo those insertions perfectly: ' +
    'you may see an extra X or a split double letter in the result. It was the first ' +
    'practical digraph cipher and saw duty in the Boer War and WWI.',
  wikiUrl: 'https://en.wikipedia.org/wiki/Playfair_cipher',
  fields: [
    {
      name: 'key',
      label: 'Keyword',
      placeholder: 'MONARCHY',
      hint: 'Builds the 5x5 square. Letters only, J folds into I.',
      generator: 'password',
      generatorSize: 8,
    },
  ],
  process: async (r) => {
    const square = buildSquare(field(r, 'key'))
    let text = ''
    for (let i = 0; i < r.input.length; i++) {
      const c = r.input[i].toUpperCase()
      if (c >= 'A' && c <= 'Z') text += c
    }
    if (text.length === 0) return { output: '' }

    const pairs = splitPairs(text)
    const encode = r.direction === 'encode'
    let out = ''
    for (const [a, b] of pairs) {
      const [r1, c1] = find(square, a)
      const [r2, c2] = find(square, b)
      if (r1 === r2) {
        out += square[r1][shift5(c1, encode ? 1 : -1)]
        out += square[r2][shift5(c2, encode ? 1 : -1)]
      } else if (c1 === c2) {
        out += square[shift5(r1, encode ? 1 : -1)][c1]
        out += square[shift5(r2, encode ? 1 : -1)][c2]
      } else {
        out += square[r1][c2]
        out += square[r2][c1]
      }
      out += ' '
    }
    return { output: out.trimEnd() }
  },
})

function buildSquare(keyword: string): string[][] {
  const seen = new Set<string>()
  const letters: string[] = []
  for (const raw of keyword.toUpperCase()) {
    if (!(raw >= 'A' && raw <= 'Z')) continue
    const ch = raw === 'J' ? 'I' : raw
    if (!seen.has(ch)) {
      seen.add(ch)
      letters.push(ch)
    }
  }
  for (let c = 65; c <= 90; c++) {
    const ch = String.fromCharCode(c)
    if (ch !== 'J' && !seen.has(ch)) {
      seen.add(ch)
      letters.push(ch)
    }
  }
  const square: string[][] = []
  for (let i = 0; i < 25; i++) {
    const row = Math.floor(i / 5)
    if (!square[row]) square[row] = []
    square[row][i % 5] = letters[i]
  }
  return square
}

function splitPairs(text: string): [string, string][] {
  const cleaned = text.replaceAll('J', 'I')
  const pairs: [string, string][] = []
  let i = 0
  while (i < cleaned.length) {
    const a = cleaned[i]
    const b = i + 1 < cleaned.length ? cleaned[i + 1] : 'X'
    if (a === b) {
      pairs.push([a, 'X'])
      i++
    } else {
      pairs.push([a, b])
      i += 2
    }
  }
  return pairs
}

function find(square: string[][], c: string): [number, number] {
  for (let r = 0; r < 5; r++)
    for (let cc = 0; cc < 5; cc++)
      if (square[r][cc] === c) return [r, cc]
  throw new CipherError(`Character '${c}' cannot live in a Playfair square.`)
}

function shift5(v: number, d: number): number {
  return mod(v + d, 5)
}

export const classicalMethods: readonly CipherMethod[] = [
  caesarMethod,
  rot13Method,
  atbashMethod,
  vigenereMethod,
  railFenceMethod,
  xorMethod,
  playfairMethod,
]
