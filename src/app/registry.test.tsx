/** Cross-method coverage the core self-test does not reach: every two-way
 * method in the registry round-trips through the same {direction, input,
 * fields} shape the store feeds it, one-way methods lock to a single
 * direction, and error paths raise CipherError instead of crashing. */
import { beforeAll, describe, expect, it } from 'vitest'

import {
  CipherError,
  findMethod,
  generateForField,
  registry,
  type CipherMethod,
} from '@/core'
import { newKey, saveKeyAscii } from '@/core/defuse'

const SAMPLE = 'The quick brown fox jumps over the lazy dog! 0123456789'

/** The fields the app store seeds for a method (spec defaults) plus
 * whatever the fixture needs to override. */
function sessionFields(
  method: CipherMethod,
  overrides: Record<string, string> = {}
): Record<string, string> {
  const fields: Record<string, string> = {}
  for (const spec of method.fields) {
    if (spec.default !== undefined) fields[spec.name] = spec.default
  }
  return { ...fields, ...overrides }
}

const KEY32 = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'
const KEY24 = '00112233445566778899aabbccddeeff0011223344556677'
const KEY8 = '0011223344556677'
const IV16 = '0f0e0d0c0b0a09080706050403020100'
const NONCE12 = '0f0e0d0c0b0a090807060504'
const IV8 = '0f0e0d0c0b0a0908'

let defuseKeyAscii: string
let rsaPair: Record<string, string>

beforeAll(async () => {
  defuseKeyAscii = saveKeyAscii(newKey())
  // The dice path the UI uses for RSA: one click fills a matched pair.
  rsaPair = await generateForField(findMethod('rsa')!, 'pub', { bits: '2048' })
})

interface RoundtripCase {
  id: string
  input?: string
  /** Lazy so fixtures can use keys minted in beforeAll. */
  fields?: () => Record<string, string>
  /** Playfair cannot be byte-exact (X insertions), so compare normalized. */
  normalize?: (text: string) => string
}

const ROUNDTRIP_CASES: readonly RoundtripCase[] = [
  { id: 'base64' },
  { id: 'base32' },
  { id: 'base58' },
  { id: 'hex' },
  { id: 'url' },
  { id: 'binary' },
  { id: 'morse', input: 'sos distress 42' },
  { id: 'caesar', input: 'Attack at Dawn! 123', fields: () => ({ shift: '7' }) },
  { id: 'rot13' },
  { id: 'atbash' },
  { id: 'vigenere', fields: () => ({ key: 'LEMONKEY' }) },
  { id: 'railfence', fields: () => ({ rails: '4' }) },
  { id: 'xor', fields: () => ({ key: 'secret key' }) },
  {
    id: 'playfair',
    input: 'attackatdawn',
    fields: () => ({ key: 'playfair example' }),
    normalize: (t) => t.replace(/[^A-Za-z]/g, '').toUpperCase(),
  },
  { id: 'aes-cbc', fields: () => ({ key: KEY32, iv: IV16 }) },
  { id: 'aes-gcm', fields: () => ({ key: KEY32, iv: NONCE12 }) },
  { id: 'aes-ecb', fields: () => ({ key: KEY32 }) },
  { id: 'des', fields: () => ({ key: KEY8, iv: IV8 }) },
  { id: '3des', fields: () => ({ key: KEY24, iv: IV8 }) },
  { id: 'defuse-encrypt', fields: () => ({ key: defuseKeyAscii }) },
  {
    id: 'defuse-password',
    input: 'open sesame please',
    fields: () => ({ password: 'correct horse battery staple' }),
  },
  {
    id: 'mcrypt',
    fields: () => ({
      algo: 'rijndael-128',
      mode: 'cbc',
      key: KEY32,
      keyenc: 'Hex',
      iv: IV16,
      ivenc: 'Hex',
      out: 'Base64',
    }),
  },
  {
    id: 'laravel-crypt',
    fields: () => ({ key: KEY32, keyenc: 'Hex', cipher: 'rijndael-128' }),
  },
]

describe('registry roundtrips through the session shape', () => {
  it.each(ROUNDTRIP_CASES)('$id encodes then decodes back to the input', async (c) => {
    const method = findMethod(c.id)
    expect(method).toBeDefined()
    expect(method!.twoWay).toBe(true)

    const input = c.input ?? SAMPLE
    const fields = sessionFields(method!, c.fields?.() ?? {})
    const normalize = c.normalize ?? ((t: string) => t)

    const encoded = await method!.process({ direction: 'encode', input, fields })
    expect(encoded.output.length).toBeGreaterThan(0)

    const decoded = await method!.process({
      direction: 'decode',
      input: encoded.output,
      fields,
    })
    expect(normalize(decoded.output)).toBe(normalize(input))
  })

  it('covers every two-way method except the RSA-backed trio, which follow below', () => {
    const covered = new Set([
      ...ROUNDTRIP_CASES.map((c) => c.id),
      'rsa',
      'rsa-sign',
      'jwt',
      'jwks',
      'defuse-key',
    ])
    const twoWay = registry.filter((m) => m.twoWay).map((m) => m.id)
    expect(twoWay.every((id) => covered.has(id))).toBe(true)
    expect(twoWay).toHaveLength(28)
  })

  it('rsa encrypt/decrypt roundtrips with the dice-generated pair', async () => {
    const method = findMethod('rsa')!
    const encoded = await method.process({
      direction: 'encode',
      input: 'a tiny secret',
      fields: rsaPair,
    })
    expect(encoded.note).toContain('RSA-2048')
    const decoded = await method.process({
      direction: 'decode',
      input: encoded.output,
      fields: rsaPair,
    })
    expect(decoded.output).toBe('a tiny secret')

    const verdict = await method.validateFields!(rsaPair)
    expect(verdict.overall).toContain('verified')
  })

  it('rsa sign/verify roundtrips and a mismatched message fails loudly', async () => {
    const method = findMethod('rsa-sign')!
    const signed = await method.process({
      direction: 'encode',
      input: 'the message',
      fields: rsaPair,
    })
    const verified = await method.process({
      direction: 'decode',
      input: 'the message',
      fields: { ...rsaPair, sig: signed.output },
    })
    expect(verified.output).toContain('VALID')

    await expect(
      method.process({
        direction: 'decode',
        input: 'another message',
        fields: { ...rsaPair, sig: signed.output },
      })
    ).rejects.toThrow(CipherError)
    await expect(
      method.process({
        direction: 'decode',
        input: 'another message',
        fields: { ...rsaPair, sig: signed.output },
      })
    ).rejects.toThrow('Signature INVALID')
  })

  it('jwt signs HS256, decodes with verify, and warns on a wrong secret', async () => {
    const method = findMethod('jwt')!
    const fields = { alg: 'HS256', secret: 's3cret' }
    const signed = await method.process({
      direction: 'encode',
      input: '{"sub":"42","name":"QA"}',
      fields,
    })
    expect(signed.output.split('.')).toHaveLength(3)

    const decoded = await method.process({
      direction: 'decode',
      input: signed.output,
      fields,
    })
    expect(decoded.note).toContain('checks out')
    expect(decoded.output).toContain('"sub": "42"')

    const wrong = await method.process({
      direction: 'decode',
      input: signed.output,
      fields: { alg: 'HS256', secret: 'nope' },
    })
    expect(wrong.warning).toBeDefined()
    // The header/payload still render even when verification fails.
    expect(wrong.output).toContain('"sub": "42"')
  })

  it('jwks builds a key set from the private key and inspects it back', async () => {
    const method = findMethod('jwks')!
    const built = await method.process({
      direction: 'encode',
      input: '',
      fields: { priv: rsaPair['priv'], kid: 'qa-kid' },
    })
    expect(built.output).toContain('"kty": "RSA"')

    const inspected = await method.process({
      direction: 'decode',
      input: built.output,
      fields: {},
    })
    expect(inspected.output).toContain('qa-kid')
    expect(inspected.output).toContain('BEGIN PRIVATE KEY')
    expect(inspected.note).toContain('1 key(s)')
  })

  it('defuse key tool wraps a key with a password and unlocks it back', async () => {
    const method = findMethod('defuse-key')!
    const fields = {
      mode: 'Wrap key with password (def10000)',
      key: defuseKeyAscii,
      password: 'wrap-pass',
    }
    const wrapped = await method.process({ direction: 'encode', input: 'x', fields })
    expect(wrapped.output).toMatch(/^def10000/)

    const unlocked = await method.process({
      direction: 'decode',
      input: wrapped.output,
      fields: { password: 'wrap-pass' },
    })
    expect(unlocked.output).toBe(defuseKeyAscii)
  })
})

describe('one-way methods', () => {
  const ONE_WAY_IDS = [
    'md5',
    'sha1',
    'sha256',
    'sha384',
    'sha512',
    'sha3-256',
    'hmac-md5',
    'hmac-sha1',
    'hmac-sha256',
    'hmac-sha512',
    'crc32',
    'pbkdf2',
    'defuse-legacy',
  ]

  it('registry has 41 methods, exactly 13 of them one-way', () => {
    expect(registry).toHaveLength(41)
    expect(registry.filter((m) => !m.twoWay).map((m) => m.id)).toEqual(ONE_WAY_IDS)
  })

  it.each(ONE_WAY_IDS.filter((id) => id !== 'defuse-legacy'))(
    '$id produces a stable digest across runs',
    async (id) => {
      const method = findMethod(id)!
      const fields: Record<string, string> =
        id.startsWith('hmac-')
          ? { key: KEY8 }
          : id === 'pbkdf2'
            ? { password: 'hunter2', salt: 'salty', iterations: '10' }
            : {}
      const first = await method.process({ direction: 'encode', input: 'stability', fields })
      const second = await method.process({ direction: 'encode', input: 'stability', fields })
      expect(first.output).toBe(second.output)
      expect(first.output.length).toBeGreaterThan(0)
    }
  )

  it('defuse-legacy decrypts the PHP v1 vector deterministically', async () => {
    const vectors = (await import('../../tests/vectors.json')).default as {
      legacy_kat?: { key_hex: string; plaintext: string; ciphertext_hex: string }
    }
    const kat = vectors.legacy_kat
    expect(kat).toBeDefined()
    const method = findMethod('defuse-legacy')!
    const decode = () =>
      method.process({ direction: 'decode', input: kat!.ciphertext_hex, fields: { key: kat!.key_hex } })
    expect((await decode()).output).toBe(kat!.plaintext)
    expect((await decode()).output).toBe(kat!.plaintext)
  })

  it('sha-256 of abc matches the known answer and crc32 carries its note', async () => {
    const sha256 = await findMethod('sha256')!.process({
      direction: 'encode',
      input: 'abc',
      fields: {},
    })
    expect(sha256.output).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    )

    const crc = await findMethod('crc32')!.process({
      direction: 'encode',
      input: 'The quick brown fox jumps over the lazy dog',
      fields: {},
    })
    expect(crc.output).toBe('414fa339')
    expect(crc.note).toBe('0x414FA339')
  })
})

describe('error paths raise CipherError, never crash', () => {
  it('bad base64 input throws a friendly error', async () => {
    await expect(
      findMethod('base64')!.process({ direction: 'decode', input: '###', fields: {} })
    ).rejects.toThrow('Base64 input contains invalid characters.')
  })

  it('wrong AES key size names the sizes it wanted', async () => {
    await expect(
      findMethod('aes-gcm')!.process({
        direction: 'encode',
        input: 'hello',
        fields: { key: 'abcd', iv: NONCE12, keyenc: 'Hex', ivenc: 'Hex' },
      })
    ).rejects.toThrow('Got 2')
  })

  it('an empty hex key says it is empty, not that the length is odd', async () => {
    await expect(
      findMethod('des')!.process({
        direction: 'encode',
        input: 'hello',
        fields: { key: '', keyenc: 'Hex' },
      })
    ).rejects.toThrow('Hex input is empty.')
  })

  it('tampered GCM ciphertext fails authentication', async () => {
    const method = findMethod('aes-gcm')!
    const fields = { key: KEY32, iv: NONCE12, keyenc: 'Hex', ivenc: 'Hex', out: 'Base64' }
    const encoded = await method.process({ direction: 'encode', input: 'tamper me', fields })
    const flipped =
      encoded.output.slice(0, 8) +
      (encoded.output[8] === 'A' ? 'B' : 'A') +
      encoded.output.slice(9)
    await expect(
      method.process({ direction: 'decode', input: flipped, fields })
    ).rejects.toThrow('Authentication failed')
  })

  it('defuse bad checksum surfaces the integrity failure', async () => {
    const method = findMethod('defuse-encrypt')!
    const fields = { key: defuseKeyAscii }
    const encoded = await method.process({ direction: 'encode', input: 'do not touch', fields })
    const flipped =
      encoded.output.slice(0, -1) +
      (encoded.output.endsWith('0') ? '1' : '0')
    await expect(
      method.process({ direction: 'decode', input: flipped, fields })
    ).rejects.toThrow('Integrity check failed')
  })
})
