/** A faithful TypeScript port of the string-encryption core of
 * defuse/php-encryption (https://github.com/defuse/php-encryption),
 * verified against the PHP library with generated cross-language test
 * vectors (tests/vectors.json, regenerated from a fresh PHP checkout by
 * tools/gen-vectors.php in CI).
 *
 * Wire format (v2, master as of 2025):
 *   hex( DE F5 02 00 || salt(32) || IV(16) || AES-256-CTR ciphertext || HMAC-SHA256(32) )
 * so every ciphertext string starts with "def50200". The HMAC covers
 * everything before it. Keys are stored as
 *   hex( DE F0 00 00 || 32 raw bytes || SHA-256 checksum )
 * which is why they start with "def00000".
 */
import { CipherError } from './types'
import {
  hex,
  unhex,
  utf8Encode,
  utf8Decode,
  hkdfSha256,
  pbkdf2Sha256,
  hmacSha256,
  sha256,
  aesCtr,
  fixedTimeEquals,
  randomBytes,
} from './primitives'
import { aesCbcDecrypt } from './aes'

export const HEADER_VERSION_SIZE = 4
export const MINIMUM_CIPHERTEXT_SIZE = 84 // header + salt + iv + mac, empty plaintext
export const BLOCK_SIZE = 16
export const KEY_SIZE = 32
export const SALT_SIZE = 32
export const MAC_SIZE = 32
export const PBKDF2_ITERATIONS = 100_000

const CIPHERTEXT_HEADER = [0xde, 0xf5, 0x02, 0x00]
const KEY_HEADER = [0xde, 0xf0, 0x00, 0x00]
const PROTECTED_KEY_HEADER = [0xde, 0xf1, 0x00, 0x00]

const ENCRYPTION_INFO = 'DefusePHP|V2|KeyForEncryption'
const AUTHENTICATION_INFO = 'DefusePHP|V2|KeyForAuthentication'
const LEGACY_ENCRYPTION_INFO = 'DefusePHP|KeyForEncryption'
const LEGACY_AUTHENTICATION_INFO = 'DefusePHP|KeyForAuthentication'

// ------------------------------------------------------------ keys

export function newKey(): Uint8Array {
  return randomBytes(KEY_SIZE)
}

/** A ready-to-paste def00000... key string. */
export function newKeyAscii(): string {
  return saveKeyAscii(newKey())
}

export function saveKeyAscii(rawKey: Uint8Array): string {
  if (rawKey.length !== KEY_SIZE) throw new CipherError('A defuse key must be exactly 32 bytes.')
  return hex(wrapChecksummed(KEY_HEADER, rawKey))
}

/** Accepts trailing whitespace the way the PHP loader does, and
 * verifies the embedded SHA-256 checksum. */
export function loadKeyAscii(saved: string): Uint8Array {
  const bytes = loadChecksummed(KEY_HEADER, saved, 'key')
  if (bytes.length !== KEY_SIZE)
    throw new CipherError('A defuse key must carry exactly 32 bytes of key material.')
  return bytes
}

export function tryValidateKeyAscii(saved: string): { ok: boolean; error: string } {
  try {
    loadKeyAscii(saved)
    return { ok: true, error: '' }
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) }
  }
}

// ------------------------------------------------- symmetric v2 core

/** Encrypts with a raw 32-byte key and returns the hex string. */
export function encrypt(plaintext: Uint8Array, rawKey: Uint8Array): string {
  return hex(encryptRaw(plaintext, rawKey, null, null))
}

/** Encrypts with a password (slow KDF inside) and returns hex. */
export function encryptWithPassword(plaintext: Uint8Array, passwordUtf8: Uint8Array): string {
  return hex(encryptPasswordRaw(plaintext, passwordUtf8, null, null))
}

export function encryptRaw(
  plaintext: Uint8Array,
  rawKey: Uint8Array,
  salt: Uint8Array | null,
  iv: Uint8Array | null
): Uint8Array {
  if (rawKey.length !== KEY_SIZE) throw new CipherError('The defuse key must be 32 bytes.')
  salt ??= randomBytes(SALT_SIZE)
  iv ??= randomBytes(BLOCK_SIZE)

  const [authKey, encKey] = deriveKeys(rawKey, salt)
  return seal(plaintext, salt, iv, encKey, authKey)
}

export function encryptPasswordRaw(
  plaintext: Uint8Array,
  passwordUtf8: Uint8Array,
  salt: Uint8Array | null,
  iv: Uint8Array | null
): Uint8Array {
  salt ??= randomBytes(SALT_SIZE)
  iv ??= randomBytes(BLOCK_SIZE)

  const prehash = sha256(passwordUtf8)
  const prekey = pbkdf2Sha256(prehash, salt, PBKDF2_ITERATIONS, KEY_SIZE)
  const [authKey, encKey] = deriveKeys(prekey, salt)
  return seal(plaintext, salt, iv, encKey, authKey)
}

function seal(
  plaintext: Uint8Array,
  salt: Uint8Array,
  iv: Uint8Array,
  encKey: Uint8Array,
  authKey: Uint8Array
): Uint8Array {
  const body = new Uint8Array(HEADER_VERSION_SIZE + SALT_SIZE + BLOCK_SIZE + plaintext.length)
  body.set(CIPHERTEXT_HEADER, 0)
  body.set(salt, HEADER_VERSION_SIZE)
  body.set(iv, HEADER_VERSION_SIZE + SALT_SIZE)
  body.set(aesCtr(encKey, iv, plaintext), HEADER_VERSION_SIZE + SALT_SIZE + BLOCK_SIZE)

  const mac = hmacSha256(authKey, body)
  const full = new Uint8Array(body.length + MAC_SIZE)
  full.set(body, 0)
  full.set(mac, body.length)
  return full
}

export function decryptHex(hexCiphertext: string, rawKey: Uint8Array): Uint8Array {
  const { body, mac } = openHex(hexCiphertext)
  const salt = body.subarray(HEADER_VERSION_SIZE, HEADER_VERSION_SIZE + SALT_SIZE)
  const [authKey, encKey] = deriveKeys(rawKey, salt)
  return unseal(body, mac, salt, encKey, authKey)
}

export function decryptPasswordHex(hexCiphertext: string, passwordUtf8: Uint8Array): Uint8Array {
  const { body, mac } = openHex(hexCiphertext)
  const salt = body.subarray(HEADER_VERSION_SIZE, HEADER_VERSION_SIZE + SALT_SIZE)
  const prehash = sha256(passwordUtf8)
  const prekey = pbkdf2Sha256(prehash, salt, PBKDF2_ITERATIONS, KEY_SIZE)
  const [authKey, encKey] = deriveKeys(prekey, salt)
  return unseal(body, mac, salt, encKey, authKey)
}

function openHex(hexCiphertext: string): { body: Uint8Array; mac: Uint8Array } {
  let raw: Uint8Array
  try {
    raw = unhex(hexCiphertext.trim())
  } catch {
    throw new CipherError('This does not look like a defuse ciphertext (invalid hex).')
  }
  if (raw.length < MINIMUM_CIPHERTEXT_SIZE)
    throw new CipherError('The ciphertext is too short to be a defuse v2 message.')
  if (!fixedTimeEquals(raw.subarray(0, HEADER_VERSION_SIZE), Uint8Array.from(CIPHERTEXT_HEADER)))
    throw new CipherError(
      'Bad version header. This string was not produced by defuse/php-encryption v2, or it is corrupted.'
    )
  return { body: raw.subarray(0, raw.length - MAC_SIZE), mac: raw.subarray(raw.length - MAC_SIZE) }
}

function unseal(
  body: Uint8Array,
  mac: Uint8Array,
  _salt: Uint8Array,
  encKey: Uint8Array,
  authKey: Uint8Array
): Uint8Array {
  const expected = hmacSha256(authKey, body)
  if (!fixedTimeEquals(expected, mac))
    throw new CipherError(
      'Integrity check failed. Either the key/password is wrong or the ciphertext was modified.'
    )
  const iv = body.subarray(HEADER_VERSION_SIZE + SALT_SIZE, HEADER_VERSION_SIZE + SALT_SIZE + BLOCK_SIZE)
  const ct = body.subarray(HEADER_VERSION_SIZE + SALT_SIZE + BLOCK_SIZE)
  return aesCtr(encKey, iv, ct)
}

/** HKDF-SHA256 splitting a secret into the two v2 subkeys. */
export function deriveKeys(ikm: Uint8Array, salt: Uint8Array): [Uint8Array, Uint8Array] {
  return [
    hkdfSha256(ikm, salt, AUTHENTICATION_INFO, KEY_SIZE),
    hkdfSha256(ikm, salt, ENCRYPTION_INFO, KEY_SIZE),
  ]
}

// ------------------------------------- password-protected key (v2)

/** Wraps a fresh random key with a password, mirroring
 * KeyProtectedByPassword::createRandomPasswordProtectedKey. */
export function createPasswordProtectedKey(password: string): string {
  return wrapProtected(newKey(), password)
}

export function wrapProtected(innerKey: Uint8Array, password: string): string {
  // The PHP library hashes the password first, as domain separation,
  // then hands the raw digest to encryptWithPassword.
  const passwordDigest = sha256(utf8Encode(password))
  const wrapped = encryptPasswordRaw(utf8Encode(saveKeyAscii(innerKey)), passwordDigest, null, null)
  return hex(wrapChecksummed(PROTECTED_KEY_HEADER, wrapped))
}

/** Unlocks a password-protected key, returning the raw 32 bytes. */
export function unlockProtectedKey(saved: string, password: string): Uint8Array {
  const wrapped = loadChecksummed(PROTECTED_KEY_HEADER, saved, 'password-protected key')
  const passwordDigest = sha256(utf8Encode(password))
  const innerAscii = utf8Decode(decryptPasswordHex(hex(wrapped), passwordDigest))
  return loadKeyAscii(innerAscii)
}

// --------------------------------------------------------- legacy v1

/** Decrypts ciphertext from version 1.x of the library:
 * HMAC(32) || IV(16) || AES-128-CBC, keys split by HKDF with a zero salt. */
export function legacyDecrypt(hexCiphertext: string, keyBytes: Uint8Array): Uint8Array {
  if (keyBytes.length !== 16)
    throw new CipherError('The legacy format uses a 16-byte key.')

  let raw: Uint8Array
  try {
    raw = unhex(hexCiphertext.trim())
  } catch {
    throw new CipherError('Legacy input is not valid hex.')
  }
  if (raw.length <= 16 + 32) throw new CipherError('The legacy ciphertext is too short.')

  const mac = raw.subarray(0, 32)
  const message = raw.subarray(32)

  const akey = hkdfSha256(keyBytes, new Uint8Array(32), LEGACY_AUTHENTICATION_INFO, 16)
  if (!fixedTimeEquals(hmacSha256(akey, message), mac))
    throw new CipherError('Integrity check failed. Wrong key or modified ciphertext.')

  const ekey = hkdfSha256(keyBytes, new Uint8Array(32), LEGACY_ENCRYPTION_INFO, 16)
  const iv = message.subarray(0, 16)
  const ct = message.subarray(16)

  try {
    return aesCbcDecrypt(ekey, iv, ct)
  } catch {
    throw new CipherError('Decryption failed. The ciphertext is not valid AES-128-CBC data.')
  }
}

// -------------------------------------------------------- checksums

function wrapChecksummed(header: number[], payload: Uint8Array): Uint8Array {
  const checkedBytes = new Uint8Array(header.length + payload.length)
  checkedBytes.set(header, 0)
  checkedBytes.set(payload, header.length)
  const checksum = sha256(checkedBytes)
  const full = new Uint8Array(checkedBytes.length + checksum.length)
  full.set(checkedBytes, 0)
  full.set(checksum, checkedBytes.length)
  return full
}

function loadChecksummed(expectedHeader: number[], saved: string, what: string): Uint8Array {
  const text = saved.replace(/[\r\n\0\t ]+$/, '')
  let bytes: Uint8Array
  try {
    bytes = unhex(text)
  } catch {
    throw new CipherError(`This is not a valid defuse ${what} string (invalid hex).`)
  }
  if (bytes.length < HEADER_VERSION_SIZE + 32)
    throw new CipherError(`The defuse ${what} string is shorter than expected.`)
  if (!fixedTimeEquals(bytes.subarray(0, HEADER_VERSION_SIZE), Uint8Array.from(expectedHeader)))
    throw new CipherError(`Invalid header. Expected a defuse ${what} string.`)
  const checkedBytes = bytes.subarray(0, bytes.length - 32)
  const checksum = bytes.subarray(bytes.length - 32)
  if (!fixedTimeEquals(sha256(checkedBytes), checksum))
    throw new CipherError('Checksum mismatch. The key string is corrupted.')
  return bytes.subarray(HEADER_VERSION_SIZE, bytes.length - 32)
}
