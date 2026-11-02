/** The Modern methods: AES-GCM/CBC/ECB, DES, 3DES, RSA-OAEP and RSA
 * signatures. Ported from the C# Methods_Modern with the explainer copy
 * intact. AES modes come from @noble/ciphers and aes-js, DES/3DES from
 * des.js, RSA from the webview's WebCrypto (rsa.ts). */
import {
  CipherError,
  defineMethod,
  field,
  validation,
  emptyValidation,
  type CipherMethod,
  type CipherResult,
  type FieldSpec,
  type FieldValidation,
} from './types'
import {
  base64,
  hex,
  unbase64,
  unhex,
  utf8Encode,
  utf8Decode,
  randomBytes,
  decodeKeyMaterial,
  KEY_ENCODINGS,
} from './primitives'
import {
  aesGcmEncrypt,
  aesGcmDecrypt,
  aesCbcEncrypt,
  aesCbcDecrypt,
  aesEcbEncrypt,
  aesEcbDecrypt,
  desCbc,
  tripleDesCbc,
} from './aes'
import {
  generateRsaPemPair,
  importRsaPems,
  oaepEncrypt,
  oaepDecrypt,
  rsassaSign,
  rsassaVerify,
  type RsaBits,
} from './rsa'

type BlockAlgorithm = 'AES' | 'DES' | 'TripleDES'

interface BlockCipherSpec {
  id: string
  name: string
  blurb: string
  learn: string
  wiki: string
  algorithm: BlockAlgorithm
  keySizes: readonly number[]
  ivSize: number
  mode: 'CBC' | 'ECB'
  gcm?: boolean
  warning?: string
  aliases?: string[]
}

function blockCipherMethod(spec: BlockCipherSpec): CipherMethod {
  const fields: FieldSpec[] = [
    {
      name: 'key',
      label: 'Key',
      secret: true,
      placeholder: spec.keySizes.map((b) => `${b} bytes`).join(' / '),
      hint: `${spec.keySizes.map((b) => b * 8).join(', ')}-bit. ${spec.keySizes.join(', ')} bytes.`,
      generator: 'hexBytes',
      generatorSize: spec.keySizes[spec.keySizes.length - 1],
    },
    {
      name: 'keyenc',
      label: 'Key encoding',
      kind: 'dropdown',
      options: KEY_ENCODINGS,
      default: 'Hex',
    },
  ]
  if (spec.ivSize > 0) {
    fields.push(
      {
        name: 'iv',
        label: spec.gcm ? 'Nonce' : 'IV',
        placeholder: spec.gcm ? '12 bytes' : `${spec.ivSize} bytes`,
        hint: spec.gcm
          ? 'Number used ONCE. Reusing a nonce with the same key breaks GCM completely.'
          : 'Initialisation vector. Different every message, not secret.',
        generator: 'hexBytes',
        generatorSize: spec.ivSize,
      },
      {
        name: 'ivenc',
        label: spec.gcm ? 'Nonce encoding' : 'IV encoding',
        kind: 'dropdown',
        options: KEY_ENCODINGS,
        default: 'Hex',
      }
    )
  }
  fields.push({
    name: 'out',
    label: 'Output',
    kind: 'dropdown',
    options: ['Base64', 'Hex'],
    default: 'Base64',
  })

  return defineMethod({
    id: spec.id,
    name: spec.name,
    category: 'Modern',
    blurb: spec.blurb,
    learn: spec.learn,
    wikiUrl: spec.wiki,
    aliases: spec.aliases ?? [],
    fields,
    process: async (r): Promise<CipherResult> => {
      const key = decodeKeyMaterial(field(r, 'key'), field(r, 'keyenc'))
      if (!spec.keySizes.includes(key.length))
        throw new CipherError(
          `${spec.name} needs a ${spec.keySizes.map((s) => s * 8).join(' or ')}-bit key ` +
            `(${spec.keySizes.join('/') } bytes). Got ${key.length}.`
        )

      if (spec.gcm) return processGcm(r, key)

      let iv: Uint8Array = new Uint8Array(0)
      let note: string | undefined
      if (spec.ivSize > 0) {
        const ivText = field(r, 'iv').trim()
        if (r.direction === 'encode' && ivText.length === 0) {
          iv = randomBytes(spec.ivSize)
          note =
            `No IV given, so a random one was used (${hex(iv)}). ` +
            'Copy it if you want to decrypt later.'
        } else {
          iv = decodeKeyMaterial(ivText, field(r, 'ivenc'))
          if (iv.length !== spec.ivSize)
            throw new CipherError(`The IV must be exactly ${spec.ivSize} bytes, got ${iv.length}.`)
        }
      }

      const outputEncoding = field(r, 'out')
      try {
        if (r.direction === 'encode') {
          const ct = transform(spec, utf8Encode(r.input), key, iv, true)
          return { output: renderBytes(ct, outputEncoding), note, warning: spec.warning }
        }
        const pt = transform(spec, decodeInput(r.input, outputEncoding), key, iv, false)
        return { output: utf8Decode(pt), warning: spec.warning }
      } catch (e) {
        if (e instanceof CipherError) throw e
        throw new CipherError(
          'Decryption failed. Check the key, the IV and that the ' +
            'input is complete; wrong padding almost always means a wrong key.'
        )
      }
    },
  })
}

function processGcm(r: Parameters<CipherMethod['process']>[0], key: Uint8Array): CipherResult {
  const nonceText = field(r, 'iv').trim()
  if (nonceText.length === 0)
    throw new CipherError('GCM needs a nonce. The dice button rolls a safe one.')
  const nonce = decodeKeyMaterial(nonceText, field(r, 'ivenc'))
  if (nonce.length !== 12)
    throw new CipherError(`The nonce must be 12 bytes, got ${nonce.length}.`)

  const outputEncoding = field(r, 'out')
  if (r.direction === 'encode') {
    const combined = aesGcmEncrypt(key, nonce, utf8Encode(r.input))
    return {
      output: renderBytes(combined, outputEncoding),
      note: 'Ciphertext with the 16-byte tag appended.',
      warning: 'Never reuse a nonce with the same key. GCM nonce reuse leaks the key.',
    }
  }
  const data = decodeInput(r.input, outputEncoding)
  if (data.length < 16)
    throw new CipherError('Input too short: GCM output carries at least a 16-byte tag.')
  const ct = data.subarray(0, data.length - 16)
  const tag = data.subarray(data.length - 16)
  try {
    return { output: utf8Decode(aesGcmDecrypt(key, nonce, concat(ct, tag))) }
  } catch {
    throw new CipherError(
      'Authentication failed. Wrong key, wrong nonce, or the ' +
        'ciphertext was tampered with. That is GCM doing its job.'
    )
  }
}

function transform(
  spec: BlockCipherSpec,
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  encrypt: boolean
): Uint8Array {
  if (spec.algorithm === 'DES') return desCbc(key, iv, data, !encrypt)
  if (spec.algorithm === 'TripleDES') return tripleDesCbc(key, iv, data, !encrypt)
  if (spec.mode === 'ECB') return encrypt ? aesEcbEncrypt(key, data) : aesEcbDecrypt(key, data)
  return encrypt ? aesCbcEncrypt(key, iv, data) : aesCbcDecrypt(key, iv, data)
}

function decodeInput(input: string, encoding: string): Uint8Array {
  return encoding === 'Hex' ? unhex(input) : unbase64(input)
}

function renderBytes(bytes: Uint8Array, encoding: string): string {
  return encoding === 'Hex' ? hex(bytes) : base64(bytes)
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length)
  out.set(a, 0)
  out.set(b, a.length)
  return out
}

// -------------------------------------------------------------- rsa

const RSA_BITS_FIELD: FieldSpec = {
  name: 'bits',
  label: 'Key size',
  kind: 'dropdown',
  options: ['2048', '3072', '4096'],
  default: '2048',
}

async function parseBits(value: string | undefined): Promise<RsaBits> {
  const bits = Number.parseInt(value ?? '2048', 10)
  return (bits === 3072 || bits === 4096 ? bits : 2048) as RsaBits
}

export const rsaMethod: CipherMethod = defineMethod({
  id: 'rsa',
  name: 'RSA Encrypt (OAEP)',
  category: 'Modern',
  blurb: 'Public key encrypts, only the private key reads it back.',
  learn:
    'RSA is asymmetric: what one key locks, only its partner opens. You hand out the ' +
    'public key to everyone and keep the private one offline. Encrypting to a person ' +
    'means using THEIR public key. Real protocols never RSA-encrypt the message itself, ' +
    'only a fresh AES key (hybrid encryption), because RSA can only encrypt a few ' +
    'hundred bytes and is slow. This tool uses OAEP padding with SHA-256, the safe way.',
  wikiUrl: 'https://en.wikipedia.org/wiki/RSA_(cryptosystem)',
  fields: [
    {
      name: 'pub',
      label: 'Public key (PEM)',
      kind: 'multiline',
      placeholder: '-----BEGIN PUBLIC KEY-----',
      hint: 'Used to encrypt. Click the dice to generate a matched pair.',
      generator: 'rsaKeyPair',
    },
    {
      name: 'priv',
      label: 'Private key (PEM)',
      kind: 'multiline',
      secret: true,
      placeholder: '-----BEGIN PRIVATE KEY-----',
      hint: 'Used to decrypt. The dice fills both keys together.',
      generator: 'rsaKeyPair',
    },
    RSA_BITS_FIELD,
  ],
  process: async (r): Promise<CipherResult> => {
    if (r.direction === 'encode') {
      const keys = await importForEncrypt(r)
      const data = utf8Encode(r.input)
      let ct: Uint8Array
      try {
        ct = await oaepEncrypt(keys.public, data)
      } catch {
        throw new CipherError(
          `The message is too long for RSA-${keys.bits} with OAEP ` +
            `(limit is ${keys.bits / 8 - 62} bytes). RSA is for small payloads; ` +
            'use it to wrap an AES key in real systems.'
        )
      }
      return {
        output: base64(ct),
        note: `RSA-${keys.bits} with OAEP/SHA-256 padding.`,
      }
    }

    const priv = field(r, 'priv').trim()
    if (priv.length === 0) throw new CipherError('Decryption needs the private key.')
    const keys = await importRsaPems(undefined, priv)
    let ct: Uint8Array
    try {
      ct = unbase64(r.input)
    } catch {
      throw new CipherError('The input is not valid Base64 ciphertext.')
    }
    try {
      const pt = await oaepDecrypt(keys.private as CryptoKey, ct)
      return { output: utf8Decode(pt) }
    } catch (e) {
      if (e instanceof CipherError) throw e
      throw new CipherError(
        'Decryption failed. This ciphertext does not match ' +
          'this key, or it was not encrypted with OAEP/SHA-256.'
      )
    }
  },
  validateFields: async (values): Promise<FieldValidation> => {
    const result = emptyValidation()
    const pubText = (values['pub'] ?? '').trim()
    const privText = (values['priv'] ?? '').trim()

    let pub: Awaited<ReturnType<typeof importRsaPems>> | null = null
    let priv: Awaited<ReturnType<typeof importRsaPems>> | null = null
    if (pubText.length > 0) {
      try {
        pub = await importRsaPems(pubText, undefined)
        result.fields['pub'] = validation.good(`Valid public key, ${pub.bits}-bit`)
      } catch (e) {
        result.fields['pub'] = validation.bad(e instanceof Error ? e.message : String(e))
      }
    }
    if (privText.length > 0) {
      try {
        priv = await importRsaPems(undefined, privText)
        result.fields['priv'] = validation.good(`Valid private key, ${priv.bits}-bit`)
      } catch (e) {
        result.fields['priv'] = validation.bad(e instanceof Error ? e.message : String(e))
      }
    }

    if (pub && priv) {
      let match
      try {
        const probe = await oaepEncrypt(pub.public, new Uint8Array([1, 2, 3]))
        const back = await oaepDecrypt(priv.private as CryptoKey, probe)
        match = back.length === 3 && back[0] === 1 && back[1] === 2 && back[2] === 3
      } catch {
        match = false
      }
      result.overall = match
        ? 'Key pair verified: the private key unlocks the public key.'
        : 'These two keys do NOT belong to the same pair.'
      if (!match) {
        result.fields['pub'] = validation.bad('Does not pair with the private key below')
        result.fields['priv'] = validation.bad('Does not pair with the public key above')
      }
    } else if (pub || priv) {
      result.overall = 'One key present. The dice generates a matched pair in one click.'
    }
    return result
  },
  generate: async (_f, current) => toRecord(await generateRsaPemPair(await parseBits(current['bits']))),
})

/** Widen the PEM pair to the plain record the registry contract expects. */
function toRecord(pair: { pub: string; priv: string }): Record<string, string> {
  return { pub: pair.pub, priv: pair.priv }
}

async function importForEncrypt(r: Parameters<CipherMethod['process']>[0]) {
  const pub = field(r, 'pub').trim()
  if (pub.length > 0) return importRsaPems(pub, undefined)
  const priv = field(r, 'priv').trim()
  if (priv.length > 0) return importRsaPems(undefined, priv)
  throw new CipherError(
    'Encryption needs the public key (or a private key, whose public half will be used).'
  )
}

export const rsaSignMethod: CipherMethod = defineMethod({
  id: 'rsa-sign',
  name: 'RSA Signature',
  category: 'Modern',
  blurb: 'Sign with the private key, anyone verifies with the public one.',
  learn:
    'A signature flips RSA around: the private key holder signs, and every holder of the ' +
    'public key can check the message really came from them and was not altered. ' +
    'Certificates, JWTs (RS256) and signed software updates all work this way. ' +
    'Encryption gives secrecy, signatures give authenticity: related ideas, opposite keys.',
  wikiUrl: 'https://en.wikipedia.org/wiki/Digital_signature',
  encodeLabel: 'Sign',
  decodeLabel: 'Verify',
  fields: [
    {
      name: 'priv',
      label: 'Private key (PEM)',
      kind: 'multiline',
      secret: true,
      placeholder: '-----BEGIN PRIVATE KEY-----',
      hint: 'Signs the message. Dice generates a matched pair.',
      generator: 'rsaKeyPair',
    },
    {
      name: 'pub',
      label: 'Public key (PEM)',
      kind: 'multiline',
      placeholder: '-----BEGIN PUBLIC KEY-----',
      hint: 'Verifies the signature.',
      generator: 'rsaKeyPair',
    },
    {
      name: 'sig',
      label: 'Signature (Base64)',
      kind: 'multiline',
      placeholder: 'Paste the signature here to verify...',
      hint: 'Produced by Sign, checked by Verify.',
    },
    RSA_BITS_FIELD,
  ],
  process: async (r): Promise<CipherResult> => {
    if (r.direction === 'encode') {
      const priv = field(r, 'priv').trim()
      if (priv.length === 0) throw new CipherError('Signing needs the private key.')
      const keys = await importRsaPems(undefined, priv)
      const sig = await rsassaSign(keys.private as CryptoKey, utf8Encode(r.input), 'SHA-256')
      return {
        output: base64(sig),
        note: `Signed with RSA-${keys.bits} / SHA-256 / PKCS#1 v1.5 (the RS256 recipe).`,
      }
    }

    const pub = field(r, 'pub').trim()
    if (pub.length === 0) throw new CipherError('Verifying needs the public key.')
    const sigText = field(r, 'sig').trim()
    if (sigText.length === 0) throw new CipherError('Paste the signature to verify.')
    const keys = await importRsaPems(pub, undefined)
    const sig = unbase64(sigText)
    const ok = await rsassaVerify(keys.public, sig, utf8Encode(r.input), 'SHA-256')
    if (!ok)
      throw new CipherError(
        'Signature INVALID. The message, the signature or ' +
          'the key does not match, or the text was altered after signing.'
      )
    return {
      output: 'Signature is VALID.',
      note: `Verified with RSA-${keys.bits} / SHA-256. The message is authentic and unaltered.`,
    }
  },
  validateFields: async (values): Promise<FieldValidation> => {
    const result = emptyValidation()
    const priv = (values['priv'] ?? '').trim()
    const pub = (values['pub'] ?? '').trim()
    if (priv.length > 0) {
      try {
        const k = await importRsaPems(undefined, priv)
        result.fields['priv'] = validation.good(`Valid private key, ${k.bits}-bit`)
      } catch (e) {
        result.fields['priv'] = validation.bad(e instanceof Error ? e.message : String(e))
      }
    }
    if (pub.length > 0) {
      try {
        const k = await importRsaPems(pub, undefined)
        result.fields['pub'] = validation.good(`Valid public key, ${k.bits}-bit`)
      } catch (e) {
        result.fields['pub'] = validation.bad(e instanceof Error ? e.message : String(e))
      }
    }
    return result
  },
  generate: async (_f, current) => toRecord(await generateRsaPemPair(await parseBits(current['bits']))),
})

// ---------------------------------------------------------- registry

export const modernMethods: readonly CipherMethod[] = [
  blockCipherMethod({
    id: 'aes-gcm',
    name: 'AES-256-GCM',
    blurb: 'Authenticated encryption: tampering is detected, not just decrypted wrong.',
    learn:
      'GCM encrypts and authenticates in one pass with AES under the hood. The tag at the ' +
      'end is a fingerprint of key, nonce and ciphertext together: change one bit and ' +
      'decryption refuses. This is the mode behind TLS 1.3, encrypted SQLite databases ' +
      'and age/ OpenSSL modern defaults. The one rule: a nonce must never repeat under ' +
      'the same key.',
    wiki: 'https://en.wikipedia.org/wiki/Galois/Counter_Mode',
    algorithm: 'AES',
    keySizes: [16, 24, 32],
    ivSize: 12,
    mode: 'CBC',
    gcm: true,
    aliases: ['gcm'],
  }),
  blockCipherMethod({
    id: 'aes-cbc',
    name: 'AES-CBC',
    blurb: 'Classic block chaining with PKCS#7 padding. No built-in integrity.',
    learn:
      'CBC XORs each plaintext block with the previous ciphertext block before ' +
      'encrypting, so identical blocks no longer produce identical output. The IV ' +
      'randomises the first block. Padding Oracle attacks taught the industry that CBC ' +
      'without a MAC is dangerous: always pair it with HMAC or move to GCM.',
    wiki: 'https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation',
    algorithm: 'AES',
    keySizes: [16, 24, 32],
    ivSize: 16,
    mode: 'CBC',
    aliases: ['aes'],
  }),
  blockCipherMethod({
    id: 'aes-ecb',
    name: 'AES-ECB',
    blurb: 'Every block encrypted identically. A living lesson in why modes matter.',
    learn:
      'ECB encrypts each 16-byte block independently with no chaining at all, so two ' +
      'identical blocks of plaintext produce identical ciphertext. The famous ECB ' +
      'penguin: encrypt the Linux penguin image in ECB and you can still see the penguin. ' +
      "Try encoding 'attack at dawn... attack at dawn...' with a repeated 16-byte " +
      'pattern and watch the ciphertext repeat too.',
    wiki: 'https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation',
    algorithm: 'AES',
    keySizes: [16, 24, 32],
    ivSize: 0,
    mode: 'ECB',
    warning: 'ECB is here for learning why it is dangerous. Never use it for real data.',
    aliases: ['aes'],
  }),
  blockCipherMethod({
    id: 'des',
    name: 'DES',
    blurb: '56-bit cipher from 1977. Broken by brute force in 1998.',
    learn:
      'DES was the first public crypto standard, small enough that the EFF built a ' +
      'machine (Deep Crack, $250,000) that found a DES key in 56 hours in 1998. ' +
      'Its 56-bit key space is now searched in hours on cloud GPUs. It is included ' +
      'here so you can inspect a piece of history, not to protect anything.',
    wiki: 'https://en.wikipedia.org/wiki/Data_Encryption_Standard',
    algorithm: 'DES',
    keySizes: [8],
    ivSize: 8,
    mode: 'CBC',
    warning: 'DES is broken. Educational use only.',
  }),
  blockCipherMethod({
    id: '3des',
    name: 'Triple DES',
    blurb: 'DES applied three times to stretch the key. Being retired.',
    learn:
      'Triple DES runs DES three times (encrypt, decrypt, encrypt) with two or three ' +
      'keys, giving 112-bit strength from a 56-bit cipher. It kept banks and payment ' +
      'systems running for decades, but it is slow and was formally disallowed for ' +
      'new designs by NIST in 2023.',
    wiki: 'https://en.wikipedia.org/wiki/Triple_DES',
    algorithm: 'TripleDES',
    keySizes: [16, 24],
    ivSize: 8,
    mode: 'CBC',
    warning: '3DES is deprecated. Educational use only.',
    aliases: ['tripledes', '3des'],
  }),
  rsaMethod,
  rsaSignMethod,
]
