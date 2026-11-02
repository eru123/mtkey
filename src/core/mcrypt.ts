/** The mcrypt suite: legacy PHP's encryption extension (deprecated 7.1,
 * removed 7.2), ported with its exact semantics and verified against a real
 * PHP 5.6 mcrypt via tests/mcrypt-vectors.json.
 *
 * mcrypt specifics that differ from everywhere else in this app:
 * - Block modes zero-pad the plaintext to the block size; decryption leaves
 *   the padding in. We strip trailing NULs on decode and say how many.
 * - Keys must be exactly the sizes the algorithm supports; the extension
 *   refused other lengths rather than padding them.
 * - MCRYPT_RIJNDAEL_192/256 are Rijndael with 24/32-byte BLOCKS, not AES.
 * - 'nofb'/'ncfb' are full-block OFB/CFB; the 8-bit 'ofb'/'cfb' variants
 *   are not ported (they barely appear in application code).
 *
 * Also hosts the Laravel Legacy Crypt method: the {iv, value, mac} payload
 * Laravel 3/4/5.0 wrapped around rijndael-128/256 CBC. */
import {
  CipherError,
  defineMethod,
  field,
  validation,
  emptyValidation,
  type CipherMethod,
  type CipherResult,
  type FieldValidation,
} from './types'
import {
  base64,
  hex as toHex,
  unhex,
  unbase64,
  utf8Encode,
  utf8Decode,
  randomBytes,
  hmacSha256,
  decodeKeyMaterial,
  KEY_ENCODINGS,
  fixedTimeEquals,
} from './primitives'
import { cbcNoPad, pkcs7Unpad } from './aes'
import { desBlock, edeBlock } from './aes'
import { rijndael, type BlockWords } from './rijndael'
import { blowfishCrypt } from './blowfish'
import { rc4Crypt } from './rc4'

type BlockFn = (key: Uint8Array, chunk: Uint8Array, decrypt: boolean) => Uint8Array

interface AlgorithmSpec {
  label: string
  blockSize: number
  keySizes: readonly number[]
  block: BlockFn
  stream?: boolean
  blurb: string
}

const RIJNDAEL_KEY_SIZES = [16, 24, 32]

function rijndaelBlock(nb: BlockWords): BlockFn {
  return (key, chunk, decrypt) => {
    const cipher = rijndael(nb, key)
    const out = new Uint8Array(chunk.length)
    for (let off = 0; off < chunk.length; off += cipher.blockSize)
      (decrypt ? cipher.decryptBlock : cipher.encryptBlock)(chunk, off, out, off)
    return out
  }
}

const ALGORITHMS: Record<string, AlgorithmSpec> = {
  'rijndael-128': {
    label: 'RIJNDAEL-128 (AES)',
    blockSize: 16,
    keySizes: RIJNDAEL_KEY_SIZES,
    block: rijndaelBlock(4),
    blurb: 'AES. The algorithm behind almost every mcrypt call ever written.',
  },
  'rijndael-192': {
    label: 'RIJNDAEL-192',
    blockSize: 24,
    keySizes: RIJNDAEL_KEY_SIZES,
    block: rijndaelBlock(6),
    blurb: 'Rijndael with 24-byte BLOCKS. Not AES-192; that uses 16-byte blocks.',
  },
  'rijndael-256': {
    label: 'RIJNDAEL-256',
    blockSize: 32,
    keySizes: RIJNDAEL_KEY_SIZES,
    block: rijndaelBlock(8),
    blurb: 'Rijndael with 32-byte BLOCKS, the famous "AES-256" misconfiguration.',
  },
  blowfish: {
    label: 'BLOWFISH',
    blockSize: 8,
    keySizes: Array.from({ length: 53 }, (_, i) => i + 4), // 4..56 bytes
    block: (key, chunk, decrypt) => blowfishCrypt(key, Uint8Array.from(chunk), decrypt),
    blurb: 'Blowfish, the phpMyAdmin-era favorite. Variable key length 4-56 bytes.',
  },
  des: {
    label: 'DES',
    blockSize: 8,
    keySizes: [8],
    block: desBlock,
    blurb: 'DES with a zero-padded 8-byte key.',
  },
  '3des': {
    label: '3DES (Triple DES)',
    blockSize: 8,
    keySizes: [24],
    block: edeBlock,
    blurb: 'Triple DES with the 24-byte key mcrypt required.',
  },
  arcfour: {
    label: 'ARCFOUR (RC4)',
    blockSize: 1,
    keySizes: Array.from({ length: 256 }, (_, i) => i + 1),
    block: rc4Crypt,
    stream: true,
    blurb: 'RC4, exposed as MCRYPT_ARCFOUR with mode "stream".',
  },
}

const MODES = ['cbc', 'ecb', 'nofb', 'ncfb', 'stream'] as const
type Mode = (typeof MODES)[number]

function needsIv(mode: Mode): boolean {
  return mode === 'cbc' || mode === 'nofb' || mode === 'ncfb'
}

function mcryptCrypt(
  algoName: string,
  mode: Mode,
  key: Uint8Array,
  iv: Uint8Array,
  data: Uint8Array,
  decrypt: boolean
): Uint8Array {
  const algo = ALGORITHMS[algoName]
  const bs = algo.blockSize

  if (algo.stream) return algo.block(key, data, decrypt)

  if (mode === 'ecb') {
    let work: Uint8Array
    if (!decrypt) {
      work = zeroPad(data, bs)
    } else {
      requireBlocks(data, bs)
      work = data
    }
    const out = algo.block(key, work, decrypt)
    return decrypt ? out : out
  }

  // CBC
  if (mode === 'cbc') {
    let work = data
    if (!decrypt) work = zeroPad(data, bs)
    else requireBlocks(data, bs)
    return cbcNoPad(bs, key, iv, work, algo.block, decrypt)
  }

  // NOFB: keystream blocks E(iv), E^2(iv), ... XOR data.
  if (mode === 'nofb') {
    // True output feedback: keystream block i is E(block i-1), seeded by
    // E(iv); the same keystream encrypts and decrypts.
    const out = new Uint8Array(data.length)
    let ks = algo.block(key, Uint8Array.from(iv), false)
    for (let off = 0; off < data.length; off += bs) {
      const n = Math.min(bs, data.length - off)
      for (let i = 0; i < n; i++) out[off + i] = data[off + i] ^ ks[i]
      ks = algo.block(key, ks, false)
    }
    return out
  }

  // NCFB: full-block cipher feedback, c_i = p_i XOR E(c_{i-1}) with c_0 = iv.
  // On decrypt the feedback is the INPUT ciphertext block (the same value
  // encrypt emitted), not the recovered plaintext.
  const out = new Uint8Array(data.length)
  let feedback = Uint8Array.from(iv)
  for (let off = 0; off < data.length; off += bs) {
    const n = Math.min(bs, data.length - off)
    const inBlock = Uint8Array.from(data.subarray(off, off + n))
    const ks = algo.block(key, feedback, false)
    for (let i = 0; i < n; i++) out[off + i] = data[off + i] ^ ks[i]
    if (n === bs) feedback = decrypt ? inBlock : Uint8Array.from(out.subarray(off, off + n))
  }
  return out
}

function zeroPad(data: Uint8Array, blockSize: number): Uint8Array {
  if (data.length % blockSize === 0) return data
  const padded = new Uint8Array(Math.ceil(data.length / blockSize) * blockSize)
  padded.set(data)
  return padded
}

function requireBlocks(data: Uint8Array, blockSize: number): void {
  if (data.length % blockSize !== 0)
    throw new CipherError(
      `The input length must be a multiple of ${blockSize} bytes for this mode, got ${data.length}.`
    )
}

function countTrailingZeros(data: Uint8Array): number {
  let n = 0
  for (let i = data.length - 1; i >= 0 && data[i] === 0; i--) n++
  return n
}

export const mcryptMethod: CipherMethod = defineMethod({
  id: 'mcrypt',
  name: 'mcrypt (legacy PHP)',
  category: 'PHP Interop',
  blurb: 'PHP\u2019s deleted mcrypt extension: Rijndael, Blowfish, DES, RC4 with zero padding.',
  learn:
    'mcrypt was how PHP encrypted things for fifteen years: a loose binding over libmcrypt ' +
    'that Laravel 3/4, Magento 1, old phpMyAdmin and a million bespoke apps called through ' +
    'mcrypt_encrypt(). PHP deprecated it in 7.1 and removed it in 7.2, leaving piles of ' +
    'data only this format can read. Three quirks matter. It zero-pads the plaintext to the ' +
    'block size, so decrypted text often carried invisible trailing NULs. It insisted on ' +
    'exact key lengths instead of padding keys. And MCRYPT_RIJNDAEL_192/256 select 24/32-byte ' +
    'BLOCK sizes, which is not the same as AES-192/256 - the classic misconfiguration. ' +
    'Every algorithm and mode here is verified against a real PHP 5.6 mcrypt in CI.',
  wikiUrl: 'https://www.php.net/manual/en/book.mcrypt.php',
  aliases: ['php', 'legacy', 'rijndael', 'blowfish', 'arcfour'],
  encodeLabel: 'Encrypt',
  decodeLabel: 'Decrypt',
  fields: [
    {
      name: 'algo',
      label: 'Algorithm',
      kind: 'dropdown',
      options: Object.keys(ALGORITHMS),
      default: 'rijndael-128',
      hint: 'RIJNDAEL-128 is AES; -192/-256 are the non-AES block sizes.',
    },
    {
      name: 'mode',
      label: 'Mode',
      kind: 'dropdown',
      options: MODES,
      default: 'cbc',
      hint: 'cbc/ecb zero-pad; nofb/ncfb are the full-block OFB/CFB; stream is RC4 only.',
    },
    {
      name: 'key',
      label: 'Key',
      secret: true,
      placeholder: 'the app key, exactly as PHP had it',
      hint: 'Exact length required: Rijndael 16/24/32, Blowfish 4-56, DES 8, 3DES 24 bytes.',
      generator: 'hexBytes',
      generatorSize: 32,
    },
    {
      name: 'keyenc',
      label: 'Key encoding',
      kind: 'dropdown',
      options: KEY_ENCODINGS,
      // Hex like every other symmetric method, so the hex dice yields a
      // valid key length out of the box instead of a 64-byte "text" key.
      default: 'Hex',
    },
    {
      name: 'iv',
      label: 'IV',
      placeholder: 'block-size bytes',
      hint: 'Needed for cbc/nofb/ncfb. Must be exactly one block.',
      generator: 'hexBytes',
      generatorSize: 16,
    },
    {
      name: 'ivenc',
      label: 'IV encoding',
      kind: 'dropdown',
      options: KEY_ENCODINGS,
      default: 'Hex',
    },
    {
      name: 'out',
      label: 'Output',
      kind: 'dropdown',
      options: ['Base64', 'Hex'],
      default: 'Base64',
    },
  ],
  process: async (r): Promise<CipherResult> => {
    const algoName = field(r, 'algo') || 'rijndael-128'
    const algo = ALGORITHMS[algoName]
    if (!algo) throw new CipherError('Pick one of the listed algorithms.')
    const mode = (field(r, 'mode') || 'cbc') as Mode
    if (!MODES.includes(mode)) throw new CipherError('Pick one of the listed modes.')
    if ((algo.stream === true) !== (mode === 'stream'))
      throw new CipherError(
        algo.stream
          ? 'ARCFOUR only runs in stream mode.'
          : 'stream mode only applies to ARCFOUR.'
      )

    const key = decodeKeyMaterial(field(r, 'key'), field(r, 'keyenc'))
    if (!algo.keySizes.includes(key.length))
      throw new CipherError(
        `${algo.label} needs a key of ${summarizeSizes(algo.keySizes)}; got ${key.length} bytes. ` +
          'mcrypt refused other lengths rather than padding them.'
      )

    let iv: Uint8Array = new Uint8Array(0)
    if (needsIv(mode)) {
      const ivText = field(r, 'iv').trim()
      if (ivText.length === 0) {
        if (r.direction === 'encode') {
          iv = randomBytes(algo.blockSize)
        } else {
          // Decrypting against a random IV would just yield noise; say what
          // is missing instead of letting the key decoder complain about
          // empty input.
          throw new CipherError(
            `Decrypting with ${mode.toUpperCase()} needs the original IV: exactly ${algo.blockSize} bytes for ${algo.label}.`
          )
        }
      } else {
        iv = decodeKeyMaterial(ivText, field(r, 'ivenc'))
      }
      if (iv.length !== algo.blockSize)
        throw new CipherError(
          `The IV must be exactly ${algo.blockSize} bytes for ${algo.label}, got ${iv.length}.`
        )
    }

    const outEnc = field(r, 'out')
    if (r.direction === 'encode') {
      const ct = mcryptCrypt(algoName, mode, key, iv, utf8Encode(r.input), false)
      let note = `${algo.label} / ${mode.toUpperCase()}`
      if (needsIv(mode) && field(r, 'iv').trim().length === 0)
        note += `, random IV (${toHex(iv)})`
      note += '. Plaintext was zero-padded to the block size.'
      return { output: outEnc === 'Hex' ? toHex(ct) : base64(ct), note }
    }

    let data: Uint8Array
    try {
      data = outEnc === 'Hex' ? unhex(r.input.trim()) : unbase64(r.input)
    } catch {
      throw new CipherError(`The input is not valid ${outEnc}.`)
    }
    const pt = mcryptCrypt(algoName, mode, key, iv, data, true)
    const stripped = countTrailingZeros(pt)
    const text = utf8Decode(stripped === pt.length ? new Uint8Array(0) : pt.subarray(0, pt.length - stripped))
    const note =
      stripped > 0
        ? `mcrypt's zero padding: stripped ${stripped} trailing NUL byte${stripped === 1 ? '' : 's'}.`
        : 'No zero padding was present in the decrypted bytes.'
    return { output: text, note }
  },
  validateFields: async (values): Promise<FieldValidation> => {
    const result = emptyValidation()
    const algoName = values['algo'] ?? 'rijndael-128'
    const algo = ALGORITHMS[algoName]
    const keyText = (values['key'] ?? '').trim()
    if (algo && keyText.length > 0) {
      try {
        const key = decodeKeyMaterial(keyText, values['keyenc'] ?? 'Text (UTF-8)')
        result.fields['key'] = algo.keySizes.includes(key.length)
          ? validation.good(`${key.length} bytes, valid for ${algo.label}`)
          : validation.bad(`Needs ${summarizeSizes(algo.keySizes)}; this is ${key.length} bytes.`)
      } catch (e) {
        result.fields['key'] = validation.bad(e instanceof Error ? e.message : String(e))
      }
    }
    return result
  },
})

function summarizeSizes(sizes: readonly number[]): string {
  if (sizes.length === 1) return `${sizes[0]} bytes`
  if (sizes.length <= 3) return sizes.map((s) => `${s}`).join('/') + ' bytes'
  return `${sizes[0]}-${sizes[sizes.length - 1]} bytes`
}

// ------------------------------------------------- laravel legacy crypt

const LV_CIPHERS = ['rijndael-128', 'rijndael-256']

export const laravelLegacyMethod: CipherMethod = defineMethod({
  id: 'laravel-crypt',
  name: 'Laravel Legacy Crypt',
  category: 'PHP Interop',
  blurb: 'The {iv, value, mac} payloads Laravel 3/4/5.0 encrypted with mcrypt.',
  learn:
    'Before Laravel 5.1 moved to OpenSSL, Crypt::encrypt() wrapped mcrypt: it serialize()d ' +
    'the value, PKCS7-padded it, encrypted it with RIJNDAEL-128 (some apps chose 256) in CBC ' +
    'mode using the raw app key, then published base64(json({iv, value, mac})) where mac is ' +
    'HMAC-SHA256 over the two base64 strings. Those payloads still sit in old cookies, ' +
    'sessions and database columns. Paste one here with the app key to check the MAC and ' +
    'read the plaintext; Encode mints a fresh payload the same way. The serialized PHP ' +
    'value (s:12:"...";) is shown alongside the unserialized text.',
  wikiUrl: 'https://laravel.com/docs/4.2/encryption',
  aliases: ['laravel', 'illuminate', 'php'],
  encodeLabel: 'Encrypt',
  decodeLabel: 'Decrypt',
  fields: [
    {
      name: 'key',
      label: 'App key',
      secret: true,
      placeholder: 'YourAppKey... (the raw configured string)',
      hint: 'Laravel used the key bytes as-is: 16, 24 or 32 bytes.',
      generator: 'hexBytes',
      generatorSize: 16,
    },
    {
      name: 'keyenc',
      label: 'Key encoding',
      kind: 'dropdown',
      options: KEY_ENCODINGS,
      default: 'Text (UTF-8)',
    },
    {
      name: 'cipher',
      label: 'Cipher',
      kind: 'dropdown',
      options: LV_CIPHERS,
      default: 'rijndael-128',
      hint: 'Laravel 4 defaulted to RIJNDAEL-128; some 5.0 apps configured 256.',
    },
  ],
  process: async (r): Promise<CipherResult> => {
    const key = decodeKeyMaterial(field(r, 'key'), field(r, 'keyenc'))
    if (!RIJNDAEL_KEY_SIZES.includes(key.length))
      throw new CipherError('The app key must be 16, 24 or 32 bytes.')
    const cipherName = field(r, 'cipher') || 'rijndael-128'
    const algo = ALGORITHMS[cipherName]

    if (r.direction === 'encode') {
      const serialized = phpSerialize(r.input)
      const iv = randomBytes(16)
      const padded = new Uint8Array(Math.ceil((serialized.length + 1) / 16) * 16)
      padded.set(serialized)
      const pad = padded.length - serialized.length
      padded.fill(pad, serialized.length)
      const ct = cbcNoPad(16, key, iv, padded, algo.block, false)
      const ivB64 = base64(iv)
      const valB64 = base64(ct)
      const mac = toHex(hmacSha256(key, utf8Encode(ivB64 + valB64)))
      const payload = base64(utf8Encode(`{"iv":"${ivB64}","value":"${valB64}","mac":"${mac}"}`))
      return {
        output: payload,
        note: `Fresh IV, PKCS7-padded serialized value, HMAC over the two base64 strings (${cipherName}).`,
      }
    }

    // Decrypt
    let json: { iv?: unknown; value?: unknown; mac?: unknown }
    try {
      json = JSON.parse(utf8Decode(unbase64(r.input.trim())))
    } catch {
      throw new CipherError('This does not look like a Laravel payload (outer base64 of JSON).')
    }
    if (typeof json.iv !== 'string' || typeof json.value !== 'string' || typeof json.mac !== 'string')
      throw new CipherError('The payload JSON is missing iv, value or mac.')

    const expected = toHex(hmacSha256(key, utf8Encode(json.iv + json.value)))
    if (!fixedTimeEquals(utf8Encode(expected), utf8Encode(json.mac.toLowerCase())))
      throw new CipherError(
        'MAC is invalid. Either the key is wrong or the payload was modified.'
      )

    const iv = unbase64(json.iv)
    const ct = unbase64(json.value)
    if (iv.length !== 16 || ct.length % 16 !== 0)
      throw new CipherError('The iv/value lengths do not match this cipher.')
    const padded = cbcNoPad(16, key, iv, ct, algo.block, true)
    let serialized: Uint8Array
    try {
      serialized = pkcs7Unpad(padded, 16)
    } catch {
      // Raw mcrypt data (no PKCS7): fall back to zero-strip.
      let end = padded.length
      while (end > 0 && padded[end - 1] === 0) end--
      serialized = padded.subarray(0, end)
    }
    const raw = utf8Decode(serialized)
    const preview = phpUnserialize(raw)
    return {
      output: preview !== null ? preview : raw,
      note:
        `MAC valid. ${cipherName}/CBC, PKCS7 padding.` +
        (preview !== null ? ` Serialized form: ${raw}` : ' Serialized PHP value shown raw.'),
    }
  },
})

/** PHP serialize() for strings, the only shape Laravel's Crypt::encrypt of a
 * plain string produces. */
function phpSerialize(text: string): Uint8Array {
  const bytes = utf8Encode(text)
  return utf8Encode(`s:${bytes.length}:"${text}";`)
}

/** Best-effort unserialize of scalar/flat values for display; null when the
 * shape is not one we preview. */
function phpUnserialize(raw: string): string | null {
  const m = raw.match(/^s:(\d+):"/)
  if (m) {
    const n = Number(m[1])
    const rest = raw.slice(m[0].length)
    if (rest.length >= n + 2 && rest.slice(n) === '";') return rest.slice(0, n)
    return null
  }
  if (raw === 'b:0;' || raw === 'b:1;') return raw === 'b:1;' ? 'true' : 'false'
  const i = raw.match(/^i:(-?\d+);$/)
  if (i) return i[1]
  const d = raw.match(/^d:(-?[\d.eE+]+);$/)
  if (d) return d[1]
  return null
}

export const mcryptMethods: readonly CipherMethod[] = [mcryptMethod, laravelLegacyMethod]
