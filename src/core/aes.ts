/** AES and DES block-cipher plumbing.
 *
 * - AES-GCM / AES-CBC / AES-CTR come from @noble/ciphers (audited, sync).
 *   GCM returns ciphertext with the 16-byte tag appended, matching the
 *   ct||tag wire format the old app used; CBC applies PKCS#5/7 padding by
 *   default; CTR increments the whole 16-byte IV as one big-endian counter
 *   (verified against the defuse PHP known-answer vector).
 * - AES-ECB comes from aes-js with manual PKCS#7: @noble/ciphers omits ECB
 *   on purpose, and the tool keeps ECB for its penguin-lesson value.
 * - DES / Triple DES (EDE) block cores come from des.js, the browserify
 *   reference implementation, with CBC chaining and PKCS#7 handled here.
 *   des.js EDE only accepts 24-byte keys, so 16-byte two-key material is
 *   expanded to k1||k2||k1, the same EDE convention .NET's TripleDES used.
 */
import aesjs from 'aes-js'
import { DES, EDE } from 'des.js'
import { gcm, cbc, ctr } from '@noble/ciphers/aes.js'
import { CipherError } from './types'

// ------------------------------------------------------------- pkcs7

export function pkcs7Pad(data: Uint8Array, blockSize: number): Uint8Array {
  const pad = blockSize - (data.length % blockSize)
  const out = new Uint8Array(data.length + pad)
  out.set(data, 0)
  out.fill(pad, data.length)
  return out
}

export function pkcs7Unpad(data: Uint8Array, blockSize: number): Uint8Array {
  if (data.length === 0 || data.length % blockSize !== 0) throw badPadding()
  const pad = data[data.length - 1]
  if (pad < 1 || pad > blockSize || pad > data.length) throw badPadding()
  for (let i = data.length - pad; i < data.length; i++) if (data[i] !== pad) throw badPadding()
  return data.slice(0, data.length - pad)
}

function badPadding(): CipherError {
  return new CipherError(
    'Decryption failed. Check the key, the IV and that the input is complete; wrong padding almost always means a wrong key.'
  )
}

// ---------------------------------------------------------- aes gcm

export function aesGcmEncrypt(
  key: Uint8Array,
  nonce12: Uint8Array,
  plaintext: Uint8Array
): Uint8Array {
  return gcm(key, nonce12).encrypt(plaintext)
}

export function aesGcmDecrypt(
  key: Uint8Array,
  nonce12: Uint8Array,
  ctAndTag: Uint8Array
): Uint8Array {
  return gcm(key, nonce12).decrypt(ctAndTag)
}

// ---------------------------------------------------------- aes cbc

export function aesCbcEncrypt(
  key: Uint8Array,
  iv16: Uint8Array,
  plaintext: Uint8Array
): Uint8Array {
  return cbc(key, iv16).encrypt(plaintext)
}

export function aesCbcDecrypt(
  key: Uint8Array,
  iv16: Uint8Array,
  ciphertext: Uint8Array
): Uint8Array {
  return cbc(key, iv16).decrypt(ciphertext)
}

/** Raw CBC chaining over a block primitive, no padding. Used to chain the
 * des.js block cores the same way .NET's CipherMode.CBC chained DES. */
export function cbcNoPad(
  blockSize: number,
  key: Uint8Array,
  iv: Uint8Array,
  data: Uint8Array,
  block: (key: Uint8Array, chunk: Uint8Array, decrypt: boolean) => Uint8Array,
  decrypt: boolean
): Uint8Array {
  const out = new Uint8Array(data.length)
  let prev = iv
  for (let off = 0; off < data.length; off += blockSize) {
    const chunk = new Uint8Array(data.subarray(off, off + blockSize))
    if (!decrypt) {
      const xored = new Uint8Array(blockSize)
      for (let i = 0; i < blockSize; i++) xored[i] = chunk[i] ^ prev[i]
      const enc = block(key, xored, false)
      out.set(enc, off)
      prev = enc
    } else {
      const dec = block(key, chunk, true)
      for (let i = 0; i < blockSize; i++) out[off + i] = dec[i] ^ prev[i]
      prev = chunk
    }
  }
  return out
}

// ---------------------------------------------------------- aes ctr

/** AES-CTR where all 16 IV bytes act as one big-endian counter, the
 * OpenSSL/defuse convention. @noble/ciphers' ctr does exactly this with a
 * 16-byte counter and no nonce prefix; the defuse KAT pins it. */
export function ctrFullBlock(key: Uint8Array, iv16: Uint8Array) {
  return ctr(key, iv16)
}

// ---------------------------------------------------------- aes ecb

export function aesEcbEncrypt(key: Uint8Array, plaintext: Uint8Array): Uint8Array {
  if (plaintext.length === 0) return new Uint8Array(0)
  const ecb = new aesjs.ModeOfOperation.ecb(key)
  return Uint8Array.from(ecb.encrypt(pkcs7Pad(plaintext, 16)))
}

export function aesEcbDecrypt(key: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  const ecb = new aesjs.ModeOfOperation.ecb(key)
  return pkcs7Unpad(Uint8Array.from(ecb.decrypt(ciphertext)), 16)
}

// -------------------------------------------------------------- des

type DesBlockCipher = new (options: {
  type: 'encrypt' | 'decrypt'
  key: Uint8Array
  padding: false
}) => { update(d: Uint8Array): number[] | Uint8Array; final(): number[] | Uint8Array }

/** Run a des.js block cipher over whole blocks: decrypt mode holds the
 * final block back until final(), so both halves are concatenated. */
function blockRun(Cls: DesBlockCipher, type: 'encrypt' | 'decrypt', key: Uint8Array, data: Uint8Array): Uint8Array {
  const c = new Cls({ type, key, padding: false })
  return Uint8Array.from([...c.update(data), ...c.final()])
}

export function desBlock(key: Uint8Array, data: Uint8Array, decrypt: boolean): Uint8Array {
  return blockRun(DES, decrypt ? 'decrypt' : 'encrypt', key, data)
}

export function edeBlock(key: Uint8Array, data: Uint8Array, decrypt: boolean): Uint8Array {
  // des.js EDE insists on 24 bytes; .NET allowed two-key 3DES (k1 k2 k1).
  const expanded = key.length === 16 ? Uint8Array.from([...key, ...key.subarray(0, 8)]) : key
  return blockRun(EDE, decrypt ? 'decrypt' : 'encrypt', expanded, data)
}

/** DES-CBC with PKCS#7. key: 8 bytes, iv: 8 bytes. */
export function desCbc(
  key: Uint8Array,
  iv: Uint8Array,
  data: Uint8Array,
  decrypt: boolean
): Uint8Array {
  if (key.length !== 8) throw new CipherError('DES needs an 8-byte key (56 effective bits).')
  if (data.length === 0 && !decrypt) return new Uint8Array(0)
  if (decrypt) return pkcs7Unpad(cbcNoPad(8, key, iv, data, desBlock, true), 8)
  return cbcNoPad(8, key, iv, pkcs7Pad(data, 8), desBlock, false)
}

/** 3DES-EDE-CBC with PKCS#7. key: 16 or 24 bytes, iv: 8 bytes. */
export function tripleDesCbc(
  key: Uint8Array,
  iv: Uint8Array,
  data: Uint8Array,
  decrypt: boolean
): Uint8Array {
  if (key.length !== 16 && key.length !== 24)
    throw new CipherError('Triple DES needs a 16 or 24-byte key.')
  if (data.length === 0 && !decrypt) return new Uint8Array(0)
  if (decrypt) return pkcs7Unpad(cbcNoPad(8, key, iv, data, edeBlock, true), 8)
  return cbcNoPad(8, key, iv, pkcs7Pad(data, 8), edeBlock, false)
}
