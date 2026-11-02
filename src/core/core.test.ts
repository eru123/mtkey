import { describe, expect, it } from 'vitest'
import { runSelfTest, selfTestDetail } from './selftest'
import { registry, searchMethods, findMethod } from './registry'

describe('self-test suite', () => {
  it(
    'every known-answer, roundtrip and cross-language check passes',
    async () => {
      const cases = await runSelfTest()
      const failed = cases.filter((c) => !c.pass)
      expect(failed, selfTestDetail(cases)).toEqual([])
    },
    // Three RSA keygens and four 100k-round PBKDF2 runs: slow on their own,
    // slower when vitest runs the app suite in parallel.
    30_000
  )

  it('ships 41 methods across 6 categories', () => {
    expect(registry.length).toBe(41)
    expect(new Set(registry.map((m) => m.category)).size).toBe(6)
  })
})

describe('registry', () => {
  it('finds methods by id and name, case-insensitively', () => {
    expect(findMethod('AES-GCM')?.id).toBe('aes-gcm')
    expect(findMethod('JWT')?.id).toBe('jwt')
    expect(findMethod('nope')).toBeUndefined()
  })

  it('searches across aliases so "b64" finds Base64 and "sha2" finds SHA-256', () => {
    expect(searchMethods('b64').some((m) => m.id === 'base64')).toBe(true)
    expect(searchMethods('sha2').map((m) => m.id)).toContain('sha256')
    expect(searchMethods('').length).toBe(registry.length)
  })
})
