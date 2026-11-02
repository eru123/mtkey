/** Low-level helpers shared by the cipher methods, ported from the C#
 * Mtkey.Core Primitives. Everything here is deterministic except the
 * Random* generators. Hash and KDF primitives come from @noble/hashes,
 * AES modes from @noble/ciphers and aes-js, DES from des.js; see rsa.ts
 * for the WebCrypto-based RSA half. */
import { CipherError } from './types'
import { hmac, pbkdf2, sha256Hash } from './noble'
import { ctrFullBlock } from './aes'

const utf8Encoder = new TextEncoder()
const utf8Decoder = new TextDecoder('utf-8', { fatal: true })

export function utf8Encode(text: string): Uint8Array {
  return utf8Encoder.encode(text)
}

/** Strict UTF-8 decode: invalid byte sequences throw, like the C#
 * UTF8Encoding(throwOnInvalidBytes: true) the old app used. */
export function utf8Decode(bytes: Uint8Array): string {
  try {
    return utf8Decoder.decode(bytes)
  } catch {
    throw new CipherError(
      'The result is not valid UTF-8 text. Try a different key, or decode to Hex output instead.'
    )
  }
}

// ---------------------------------------------------------------- hex

export function hex(bytes: Uint8Array): string {
  let out = ''
  for (const b of bytes) out += b.toString(16).padStart(2, '0')
  return out
}

export function unhex(text: string): Uint8Array {
  const cleaned = text.replace(/[ \r\n\t]/g, '')
  if (cleaned.length === 0) throw new CipherError('Hex input is empty.')
  if (cleaned.length % 2 !== 0)
    throw new CipherError('Hex input must have an even number of digits.')
  if (!/^[0-9a-fA-F]*$/.test(cleaned))
    throw new CipherError('Hex input contains characters other than 0-9 and a-f.')
  const bytes = new Uint8Array(cleaned.length / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(cleaned.substring(i * 2, i * 2 + 2), 16)
  return bytes
}

// ------------------------------------------------------------ base64

export function base64(bytes: Uint8Array): string {
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary)
}

export function unbase64(text: string): Uint8Array {
  const cleaned = text.replace(/[\r\n ]/g, '').replace(/=+$/, '')
  const pad = cleaned.length % 4
  if (pad === 1) throw new CipherError('Base64 input has an invalid length.')
  if (!/^[A-Za-z0-9+/]*$/.test(cleaned))
    throw new CipherError('Base64 input contains invalid characters.')
  const binary = atob(cleaned + '='.repeat((4 - pad) % 4))
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

export function base64Url(bytes: Uint8Array): string {
  return base64(bytes).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')
}

export function unbase64Url(text: string): Uint8Array {
  const b64 = text.replace(/[\r\n ]/g, '').replace(/-/g, '+').replace(/_/g, '/')
  return unbase64(b64)
}

// ------------------------------------------------------------ base32

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

export function base32(bytes: Uint8Array): string {
  let out = ''
  let buffer = 0
  let bits = 0
  for (const b of bytes) {
    buffer = (buffer << 8) | b
    bits += 8
    while (bits >= 5) {
      out += BASE32_ALPHABET[(buffer >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(buffer << (5 - bits)) & 31]
  return out
}

export function unbase32(text: string): Uint8Array {
  const cleaned = text.replace(/[= \r\n]/g, '').toUpperCase()
  if (cleaned.length === 0) throw new CipherError('Base32 input is empty.')
  const bytes: number[] = []
  let buffer = 0
  let bits = 0
  for (const c of cleaned) {
    const v = BASE32_ALPHABET.indexOf(c)
    if (v < 0) throw new CipherError(`Base32 input contains the invalid character '${c}'.`)
    buffer = (buffer << 5) | v
    bits += 5
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return new Uint8Array(bytes)
}

// ------------------------------------------------------------ base58

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

export function base58(bytes: Uint8Array): string {
  const leadingZeros = countLeading(bytes, 0)
  if (bytes.length === 0) return ''

  const b58 = new Uint8Array(bytes.length * 2)
  let length = 0
  for (let i = leadingZeros; i < bytes.length; i++) {
    let carry = bytes[i]
    for (let j = 0; j < length; j++) {
      carry += 256 * b58[j]
      b58[j] = carry % 58
      carry = (carry / 58) | 0
    }
    while (carry > 0) {
      b58[length++] = carry % 58
      carry = (carry / 58) | 0
    }
  }

  let out = '1'.repeat(leadingZeros)
  for (let i = length - 1; i >= 0; i--) out += BASE58_ALPHABET[b58[i]]
  return out
}

export function unbase58(text: string): Uint8Array {
  const cleaned = text.replace(/[ \r\n]/g, '')
  if (cleaned.length === 0) throw new CipherError('Base58 input is empty.')

  const leadingOnes = countLeading(cleaned, '1')
  const bytes: number[] = []
  for (const c of cleaned) {
    let carry = BASE58_ALPHABET.indexOf(c)
    if (carry < 0) throw new CipherError(`Base58 input contains the invalid character '${c}'.`)
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58
      bytes[j] = carry & 0xff
      carry >>= 8
    }
    while (carry > 0) {
      bytes.push(carry & 0xff)
      carry >>= 8
    }
  }

  const result = new Uint8Array(leadingOnes + bytes.length)
  for (let i = 0; i < bytes.length; i++) result[leadingOnes + i] = bytes[bytes.length - 1 - i]
  return result
}

function countLeading<T>(items: ArrayLike<T>, value: T): number {
  let n = 0
  while (n < items.length && items[n] === value) n++
  return n
}

// ------------------------------------------------------------- crc32

const CRC32_TABLE = buildCrc32Table()

function buildCrc32Table(): Uint32Array {
  const table = new Uint32Array(256)
  for (let i = 0; i < 256; i++) {
    let c = i
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    table[i] = c >>> 0
  }
  return table
}

export function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff
  for (const b of bytes) crc = (CRC32_TABLE[(crc ^ b) & 0xff] ^ (crc >>> 8)) >>> 0
  return (crc ^ 0xffffffff) >>> 0
}

// -------------------------------------------------------------- kdf

/** HKDF per RFC 5869 with HMAC-SHA256, hand-rolled over @noble/hashes so
 * the extract step matches the C# port exactly (empty salt becomes 32 zero
 * bytes). The RFC 5869 vectors in the self-test pin this down. */
export function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: string | Uint8Array,
  length: number
): Uint8Array {
  const infoBytes = typeof info === 'string' ? utf8Encoder.encode(info) : info
  const effectiveSalt = salt.length === 0 ? new Uint8Array(32) : salt
  const prk = hmac(sha256Hash, effectiveSalt, ikm)
  const okm = new Uint8Array(length)
  let t = new Uint8Array(0)
  let generated = 0
  let counter = 1
  while (generated < length) {
    const input = new Uint8Array(t.length + infoBytes.length + 1)
    input.set(t, 0)
    input.set(infoBytes, t.length)
    input[input.length - 1] = counter
    t = hmac(sha256Hash, prk, input)
    const take = Math.min(t.length, length - generated)
    okm.set(t.subarray(0, take), generated)
    generated += take
    counter++
  }
  return okm
}

/** PBKDF2-HMAC-SHA256, via @noble/hashes. */
export function pbkdf2Sha256(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  length: number
): Uint8Array {
  return pbkdf2(sha256Hash, password, salt, { c: iterations, dkLen: length })
}

export function sha256(bytes: Uint8Array): Uint8Array {
  return sha256Hash(bytes)
}

export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha256Hash, key, data)
}

/** Constant-time byte comparison, the CryptographicOperations.FixedTimeEquals
 * analogue: the accumulator never branches on data. */
export function fixedTimeEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

// ------------------------------------------------- aes ctr (openssl)

/** AES-CTR with the whole 16-byte IV as a big-endian counter, the same way
 * OpenSSL's aes-*-ctr and defuse/php-encryption treat it. nonceLength 0
 * makes every counter byte increment; the defuse known-answer vectors pin
 * this behaviour. */
export function aesCtr(key: Uint8Array, iv16: Uint8Array, data: Uint8Array): Uint8Array {
  if (iv16.length !== 16) throw new CipherError('CTR mode needs a 16-byte IV.')
  if (data.length === 0) return new Uint8Array(0)
  return ctrFullBlock(key, iv16).encrypt(data)
}

// ----------------------------------------------------------- random

export function randomBytes(count: number): Uint8Array {
  const bytes = new Uint8Array(count)
  crypto.getRandomValues(bytes)
  return bytes
}

export function randomHex(bytes: number): string {
  return hex(randomBytes(bytes))
}

export function randomBase64(bytes: number): string {
  return base64(randomBytes(bytes))
}

export function randomBase64Url(bytes: number): string {
  return base64Url(randomBytes(bytes))
}

/** Uniform random integer in [min, maxExclusive) with rejection sampling,
 * the RandomNumberGenerator.GetInt32 analogue. */
export function randomInt(min: number, maxExclusive: number): number {
  const range = maxExclusive - min
  if (range <= 0) return min
  const limit = Math.floor(0x100000000 / range) * range
  const buf = new Uint32Array(1)
  for (;;) {
    crypto.getRandomValues(buf)
    if (buf[0] < limit) return min + (buf[0] % range)
  }
}

const PASSWORD_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
const PASSWORD_SYMBOLS = '!@#$%^&*()-_=+?'

/** Readable but strong password: length 20-ish with digits, symbols
 * and mixed case guaranteed. */
export function randomPassword(length = 20): string {
  length = Math.max(12, length)
  const chars: string[] = []
  for (let i = 0; i < length - 4; i++)
    chars.push(PASSWORD_ALPHABET[randomInt(0, PASSWORD_ALPHABET.length)])
  chars.push(PASSWORD_SYMBOLS[randomInt(0, PASSWORD_SYMBOLS.length)])
  chars.push(String.fromCharCode('2'.charCodeAt(0) + randomInt(0, 8)))
  chars.push(String.fromCharCode('A'.charCodeAt(0) + randomInt(0, 26)))
  chars.push(String.fromCharCode('a'.charCodeAt(0) + randomInt(0, 26)))
  // Fisher-Yates with the CSPRNG, standing in for the C# OrderBy random key.
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomInt(0, i + 1)
    ;[chars[i], chars[j]] = [chars[j], chars[i]]
  }
  return chars.join('')
}

/** Alphanumeric token, nice for salts that humans copy around. */
export function randomToken(length = 16): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  const chars: string[] = []
  for (let i = 0; i < length; i++) chars.push(alphabet[randomInt(0, alphabet.length)])
  return chars.join('')
}

// ----------------------------------------------------------- binary

export function toBinary(bytes: Uint8Array): string {
  const parts: string[] = []
  for (const b of bytes) parts.push(b.toString(2).padStart(8, '0'))
  return parts.join(' ')
}

export function fromBinary(text: string): Uint8Array {
  const cleaned = text.replace(/[ \r\n]/g, '')
  if (cleaned.length === 0 || cleaned.length % 8 !== 0)
    throw new CipherError('Binary input must be groups of 8 bits.')
  if (!/^[01]*$/.test(cleaned))
    throw new CipherError('Binary input contains characters other than 0 and 1.')
  const bytes = new Uint8Array(cleaned.length / 8)
  for (let i = 0; i < bytes.length; i++)
    bytes[i] = parseInt(cleaned.substring(i * 8, i * 8 + 8), 2)
  return bytes
}

// ------------------------------------------------------------- keys

export type KeyEncoding = 'Hex' | 'Base64' | 'Text (UTF-8)'

export const KEY_ENCODINGS: readonly KeyEncoding[] = ['Hex', 'Base64', 'Text (UTF-8)']

/** Decode key material that the user chose to enter as hex, base64
 * or plain text. */
export function decodeKeyMaterial(value: string, encoding: string): Uint8Array {
  const trimmed = value.trim()
  switch (encoding) {
    case 'Hex':
      return unhex(trimmed)
    case 'Base64':
      return unbase64(trimmed)
    case 'Text (UTF-8)':
      return utf8Encode(trimmed)
    default:
      throw new CipherError(`Unknown key encoding ${encoding}.`)
  }
}

export function looksLikeHex(value: string): boolean {
  const t = value.replace(/ /g, '')
  return t.length > 0 && t.length % 2 === 0 && /^[0-9a-fA-F]*$/.test(t)
}
