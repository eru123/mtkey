/** Focused regression suite for the v2.1.0 PHP Interop additions: the
 * mcrypt suite and Laravel Legacy Crypt, driven through the same
 * {direction, input, fields} session shape the app store feeds process(),
 * plus the registry/search chrome the rail and palette rely on. */
import { describe, expect, it } from 'vitest'

import { CipherError, findMethod, registry, searchMethods } from '@/core'
import { CATEGORY_ICONS } from '@/app/lib'
import mcryptVectorsJson from '../../tests/mcrypt-vectors.json'

const KEY32 = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
const KEY24 = '000102030405060708090a0b0c0d0e0f1011121314151617'
const KEY16 = '00112233445566778899aabbccddeeff'
const IV16 = 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
const IV24 = 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfefff0f1f2f3f4f5f6f7'
const IV8 = 'f0f1f2f3f4f5f6f7'

/** Same seeding the app store does: spec defaults, then overrides. */
function sessionFields(overrides: Record<string, string> = {}): Record<string, string> {
  const method = findMethod('mcrypt')!
  const fields: Record<string, string> = {}
  for (const spec of method.fields) {
    if (spec.default !== undefined) fields[spec.name] = spec.default
  }
  return { ...fields, ...overrides }
}

function mcryptProcess(
  direction: 'encode' | 'decode',
  input: string,
  fields: Record<string, string>
) {
  return findMethod('mcrypt')!.process({ direction, input, fields: sessionFields(fields) })
}

interface McryptVector {
  algorithm: string
  mode: string
  key_hex: string
  iv_hex: string
  plaintext_hex: string
  ciphertext_hex: string
}

const VECTORS = mcryptVectorsJson as unknown as Record<string, McryptVector>

describe('mcrypt roundtrips through the app session shape', () => {
  interface RoundtripCase {
    label: string
    input: string
    fields: Record<string, string>
    /** Expected decode note when zero padding was added on encrypt. */
    padNote?: RegExp
    /** Expected decode note for the unpadded stream-style modes. */
    plainNote?: string
  }

  const CASES: readonly RoundtripCase[] = [
    {
      label: 'rijndael-128 cbc with a hex key',
      input: 'roundtrip a',
      fields: { algo: 'rijndael-128', mode: 'cbc', key: KEY32, keyenc: 'Hex', iv: IV16, ivenc: 'Hex' },
      padNote: /stripped 5 trailing NUL bytes/,
    },
    {
      label: 'rijndael-256 ecb (the non-AES block size)',
      input: 'big blocks',
      fields: { algo: 'rijndael-256', mode: 'ecb', key: KEY32, keyenc: 'Hex' },
      padNote: /stripped 22 trailing NUL bytes/,
    },
    {
      label: 'blowfish cbc with a 4-byte text key',
      input: 'blowfish pad',
      fields: { algo: 'blowfish', mode: 'cbc', key: 'test', keyenc: 'Text (UTF-8)', iv: IV8, ivenc: 'Hex' },
      padNote: /stripped 4 trailing NUL bytes/,
    },
    {
      label: '3des cbc',
      input: 'triple des zero pads',
      fields: { algo: '3des', mode: 'cbc', key: KEY24, keyenc: 'Hex', iv: IV8, ivenc: 'Hex' },
      padNote: /stripped 4 trailing NUL bytes/,
    },
    {
      label: 'arcfour stream',
      input: 'rc4 never pads',
      fields: { algo: 'arcfour', mode: 'stream', key: KEY16, keyenc: 'Hex' },
      plainNote: 'No zero padding was present in the decrypted bytes.',
    },
    {
      label: 'des nofb',
      input: 'nofb keeps the length',
      fields: { algo: 'des', mode: 'nofb', key: '133457799bbcdff1', keyenc: 'Hex', iv: IV8, ivenc: 'Hex' },
      plainNote: 'No zero padding was present in the decrypted bytes.',
    },
  ]

  it.each(CASES)('$label', async (c) => {
    const encoded = await mcryptProcess('encode', c.input, c.fields)
    expect(encoded.output.length).toBeGreaterThan(0)

    const decoded = await mcryptProcess('decode', encoded.output, {
      ...c.fields,
      out: 'Base64',
    })
    expect(decoded.output).toBe(c.input)
    if (c.padNote) expect(decoded.note ?? '').toMatch(c.padNote)
    if (c.plainNote) expect(decoded.note).toBe(c.plainNote)
  })

  it('an empty IV on encrypt mints a random one and notes it', async () => {
    const encoded = await mcryptProcess('encode', 'mint it', {
      algo: 'rijndael-128',
      mode: 'cbc',
      key: KEY32,
      keyenc: 'Hex',
      iv: '',
      ivenc: 'Hex',
    })
    expect(encoded.note ?? '').toMatch(/random IV \([0-9a-f]{32}\)/)
  })
})

describe('mcrypt key-length validation', () => {
  it('a wrong-length rijndael key names the sizes it wanted via process', async () => {
    await expect(
      mcryptProcess('encode', 'x', { algo: 'rijndael-128', mode: 'cbc', key: 'aabbccddee', keyenc: 'Hex', iv: IV16, ivenc: 'Hex' })
    ).rejects.toThrow(CipherError)
    await expect(
      mcryptProcess('encode', 'x', { algo: 'rijndael-128', mode: 'cbc', key: 'aabbccddee', keyenc: 'Hex', iv: IV16, ivenc: 'Hex' })
    ).rejects.toThrow('RIJNDAEL-128 (AES) needs a key of 16/24/32 bytes; got 5 bytes')
  })

  it('des wants exactly 8 bytes', async () => {
    await expect(
      mcryptProcess('encode', 'x', { algo: 'des', mode: 'cbc', key: 'aabbccddee', keyenc: 'Hex', iv: IV8, ivenc: 'Hex' })
    ).rejects.toThrow('DES needs a key of 8 bytes; got 5 bytes')
  })

  it('validateFields flags a wrong key bad and a correct key good', async () => {
    const method = findMethod('mcrypt')!

    const bad = await method.validateFields!({ algo: 'rijndael-128', key: 'aabbccddee', keyenc: 'Hex' })
    expect(bad.fields['key']?.ok).toBe(false)
    expect(bad.fields['key']?.message).toContain('Needs 16/24/32 bytes; this is 5 bytes.')

    const good = await method.validateFields!({ algo: 'rijndael-128', key: KEY32, keyenc: 'Hex' })
    expect(good.fields['key']?.ok).toBe(true)
    expect(good.fields['key']?.message).toBe('32 bytes, valid for RIJNDAEL-128 (AES)')

    const blowfish = await method.validateFields!({ algo: 'blowfish', key: 'test', keyenc: 'Text (UTF-8)' })
    expect(blowfish.fields['key']?.ok).toBe(true)
    expect(blowfish.fields['key']?.message).toBe('4 bytes, valid for BLOWFISH')
  })
})

describe('mcrypt mode and IV errors', () => {
  it('stream mode only applies to arcfour, and arcfour only runs in stream', async () => {
    await expect(
      mcryptProcess('encode', 'x', { algo: 'rijndael-128', mode: 'stream', key: KEY32, keyenc: 'Hex' })
    ).rejects.toThrow('stream mode only applies to ARCFOUR.')
    await expect(
      mcryptProcess('encode', 'x', { algo: 'arcfour', mode: 'cbc', key: KEY16, keyenc: 'Hex', iv: IV16, ivenc: 'Hex' })
    ).rejects.toThrow('ARCFOUR only runs in stream mode.')
  })

  it('a missing IV on the decrypt path names the block size it needs', async () => {
    await expect(
      mcryptProcess('decode', 'Zm9vYmFyYmFyYmFyYmFyYg==', {
        algo: 'rijndael-128',
        mode: 'cbc',
        key: KEY32,
        keyenc: 'Hex',
        iv: '',
        ivenc: 'Hex',
      })
    ).rejects.toThrow(/exactly 16 bytes/)
    await expect(
      mcryptProcess('decode', 'Zm9vYmFyYmFyYmFyYmFyYmZvb2Zvb2Zvb2Zvb2Y=', {
        algo: 'rijndael-256',
        mode: 'cbc',
        key: KEY32,
        keyenc: 'Hex',
        iv: '',
        ivenc: 'Text (UTF-8)',
      })
    ).rejects.toThrow(/exactly 32 bytes/)
  })

  it('a wrong-length IV is rejected with the exact requirement', async () => {
    await expect(
      mcryptProcess('decode', 'Zm9vYmFyYmFyYmFyYmFyYg==', {
        algo: 'rijndael-256',
        mode: 'cbc',
        key: KEY32,
        keyenc: 'Hex',
        iv: IV16, // 16 bytes, but rijndael-256 blocks are 32
        ivenc: 'Hex',
      })
    ).rejects.toThrow('The IV must be exactly 32 bytes for RIJNDAEL-256, got 16.')
  })
})

describe('mcrypt known answers from the PHP 5.6 vectors', () => {
  type KatCase = [vectorId: string, keyHex: string, keyEnc: string, ivHex: string]

  it.each([
    ['001-rijndael-128-cbc-k32-tiny', KEY32, 'Hex', IV16],
    ['033-rijndael-192-cbc-k24-tiny', KEY24, 'Hex', IV24],
    ['053-rijndael-256-ecb-k32-tiny', KEY32, 'Hex', ''],
    ['081-blowfish-cbc-k4-tiny', '74657374', 'Hex', IV8],
    ['097-des-cbc-k8-tiny', '133457799bbcdff1', 'Hex', IV8],
    ['113-3des-cbc-k24-tiny', '0123456789abcdef23456789abcdef01fedcba9876543210', 'Hex', IV8],
    ['129-arcfour-stream-k16-tiny', '0123456789abcdef0123456789abcdef', 'Hex', ''],
  ] as readonly KatCase[])('%s encrypts to the PHP ciphertext', async (id, key, keyEnc, iv) => {
    const v = VECTORS[id]
    expect(v).toBeDefined()
    expect(v.plaintext_hex).toBe('58') // the single char 'X'

    const encoded = await mcryptProcess('encode', 'X', {
      algo: v.algorithm,
      mode: v.mode,
      key,
      keyenc: keyEnc,
      iv,
      ivenc: 'Hex',
      out: 'Hex',
    })
    expect(encoded.output).toBe(v.ciphertext_hex)
  })
})

describe('laravel legacy crypt', () => {
  const LV_KEY = '3031323334353637383961626364656630313233343536373839616263646566'
  const PAYLOAD = (VECTORS['laravel4_payload'] as unknown as { payload_b64: string }).payload_b64

  function laravelProcess(
    direction: 'encode' | 'decode',
    input: string,
    fields: Record<string, string> = {}
  ) {
    const method = findMethod('laravel-crypt')!
    const seeded: Record<string, string> = {}
    for (const spec of method.fields) {
      if (spec.default !== undefined) seeded[spec.name] = spec.default
    }
    return method.process({
      direction,
      input,
      fields: { ...seeded, key: LV_KEY, keyenc: 'Hex', cipher: 'rijndael-128', ...fields },
    })
  }

  it('decodes the laravel 4 payload with a valid MAC note', async () => {
    const decoded = await laravelProcess('decode', PAYLOAD)
    expect(decoded.output).toBe('hello from laravel four')
    expect(decoded.note ?? '').toContain('MAC valid')
    expect(decoded.note ?? '').toContain('Serialized form: s:23:"hello from laravel four";')
  })

  it('a tampered payload fails the MAC instead of emitting garbage', async () => {
    const json = JSON.parse(atob(PAYLOAD)) as { iv: string; value: string; mac: string }
    await expect(laravelProcess('decode', PAYLOAD.slice(0, -4) + 'AAAA')).rejects.toThrow(
      CipherError
    )
    // Forged mac with the original value left in place.
    const badMac = btoa(JSON.stringify({ ...json, mac: 'f'.repeat(64) }))
    await expect(laravelProcess('decode', badMac)).rejects.toThrow('MAC is invalid')
    // Flipped ciphertext byte with the original mac left in place.
    const flipped =
      json.value.slice(0, 8) + (json.value[8] === 'A' ? 'B' : 'A') + json.value.slice(9)
    const badValue = btoa(JSON.stringify({ ...json, value: flipped }))
    await expect(laravelProcess('decode', badValue)).rejects.toThrow('MAC is invalid')
  })

  it('a wrong key fails the MAC, not the decryption', async () => {
    await expect(
      laravelProcess('decode', PAYLOAD, { key: KEY32, keyenc: 'Hex' })
    ).rejects.toThrow('MAC is invalid')
  })

  it('encodes to outer-base64 JSON and roundtrips through the shell', async () => {
    const encoded = await laravelProcess('encode', 'roundtrip through the shell')
    expect(encoded.output.startsWith('eyJ')).toBe(true)

    const json = JSON.parse(atob(encoded.output)) as Record<string, string>
    expect(Object.keys(json).sort()).toEqual(['iv', 'mac', 'value'])

    const decoded = await laravelProcess('decode', encoded.output)
    expect(decoded.output).toBe('roundtrip through the shell')
    expect(decoded.note ?? '').toContain('MAC valid')
  })
})

describe('php interop registry chrome', () => {
  it('search finds the new methods by name, id and alias', () => {
    expect(searchMethods('mcrypt').map((m) => m.id)).toContain('mcrypt')
    expect(searchMethods('laravel').map((m) => m.id)).toContain('laravel-crypt')
    const php = searchMethods('php').map((m) => m.id)
    expect(php).toContain('mcrypt')
    expect(php).toContain('laravel-crypt')
  })

  it('the registry counts 41 methods with exactly 6 under PHP Interop', () => {
    expect(registry).toHaveLength(41)
    const interop = registry.filter((m) => m.category === 'PHP Interop').map((m) => m.id)
    expect(interop).toEqual([
      'defuse-encrypt',
      'defuse-password',
      'defuse-key',
      'defuse-legacy',
      'mcrypt',
      'laravel-crypt',
    ])
  })

  it('every category in use resolves to a rail icon', () => {
    const categories = new Set(registry.map((m) => m.category))
    expect(categories.size).toBeGreaterThan(0)
    for (const category of categories) {
      const icon = CATEGORY_ICONS[category as keyof typeof CATEGORY_ICONS]
      // Lucide icons are React 19 forward-ref objects, not plain functions.
      expect(icon, `no icon for ${category}`).toBeDefined()
      expect(typeof icon === 'function' || 'render' in icon).toBe(true)
    }
  })
})
