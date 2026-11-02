/** Unit tests for the pure helpers in app/lib.ts. */
import { describe, expect, it } from 'vitest'

import { findMethod } from '@/core'
import {
  defaultDirection,
  formatOutputLength,
  isHeavyMethod,
  lockedDirection,
} from '@/app/lib'

describe('formatOutputLength', () => {
  it('returns empty for empty output', () => {
    expect(formatOutputLength('')).toBe('')
  })

  it('counts chars for plain text', () => {
    expect(formatOutputLength('Zm9vYmFy')).toBe('8 chars')
    expect(formatOutputLength('x'.repeat(1284))).toBe('1,284 chars')
  })

  it('reports bytes for even-length hex', () => {
    expect(formatOutputLength('00ff10')).toBe('3 B')
    expect(formatOutputLength('deadBEEF')).toBe('4 B')
  })

  it('reports bytes for mixed-case base64 with digits', () => {
    // 16 chars of base64 -> 12 bytes.
    expect(formatOutputLength('Ab3dEf7gHi9jKl2m')).toBe('12 B')
  })
})

describe('isHeavyMethod', () => {
  it('flags the heavy ids', () => {
    for (const id of ['pbkdf2', 'defuse-password', 'rsa', 'rsa-sign', 'jwks']) {
      expect(isHeavyMethod(findMethod(id)!, {})).toBe(true)
    }
  })

  it('JWT is heavy only for RS algorithms', () => {
    const jwt = findMethod('jwt')!
    expect(isHeavyMethod(jwt, { alg: 'HS256' })).toBe(false)
    expect(isHeavyMethod(jwt, { alg: 'RS256' })).toBe(true)
    expect(isHeavyMethod(jwt, {})).toBe(false)
  })

  it('base64 is never heavy', () => {
    expect(isHeavyMethod(findMethod('base64')!, {})).toBe(false)
  })
})

describe('direction locking for one-way methods', () => {
  it('hashes start on encode with their own label', () => {
    expect(defaultDirection(findMethod('sha256')!)).toBe('encode')
    expect(lockedDirection(findMethod('sha256')!)).toEqual({
      label: 'Hash',
      direction: 'encode',
    })
  })

  it('defuse legacy starts on decode, the only thing it can do', () => {
    expect(defaultDirection(findMethod('defuse-legacy')!)).toBe('decode')
    expect(lockedDirection(findMethod('defuse-legacy')!)).toEqual({
      label: 'Decrypt',
      direction: 'decode',
    })
  })
})
