/** Pure helpers shared across the app UI: category chrome, debounce
 * classification and output meta formatting. No React here. */
import {
  Braces,
  Fingerprint,
  LockKeyhole,
  Plug,
  Scroll,
  Ticket,
  type LucideIcon,
} from 'lucide-react'

import type {
  Category,
  CipherMethod,
  Direction,
  FieldSpec,
} from '@/core'

export const CATEGORY_ICONS: Record<Category, LucideIcon> = {
  Encoding: Braces,
  Classical: Scroll,
  Hash: Fingerprint,
  Modern: LockKeyhole,
  'PHP Interop': Plug,
  Tokens: Ticket,
}

/** Methods whose process() costs hundreds of milliseconds (PBKDF2 at 100k
 * rounds, RSA keygen/sign/verify). They get the 500ms trailing debounce. */
const HEAVY_METHOD_IDS = new Set([
  'pbkdf2',
  'defuse-password',
  'rsa',
  'rsa-sign',
  'jwks',
])

export function isHeavyMethod(
  method: CipherMethod,
  fields: Readonly<Record<string, string>>,
): boolean {
  if (method.id === 'jwt') return (fields['alg'] ?? '').startsWith('RS')
  return HEAVY_METHOD_IDS.has(method.id)
}

/** The direction a method starts in. Two-way methods start on the encode
 * side; a one-way method that can only decode (Defuse Legacy) starts on
 * decode. */
export function defaultDirection(method: CipherMethod): Direction {
  return method.encodeLabel !== 'n/a' ? 'encode' : 'decode'
}

/** The single locked segment label for one-way methods, with the direction
 * the method actually runs in. */
export function lockedDirection(method: CipherMethod): {
  label: string
  direction: Direction
} {
  return method.encodeLabel !== 'n/a'
    ? { label: method.encodeLabel, direction: 'encode' }
    : { label: method.decodeLabel, direction: 'decode' }
}

/** "1,284 chars" for text, "32 B" when the output is visibly a byte dump
 * (even-length hex, or base64 with mixed case and digits). */
export function formatOutputLength(output: string): string {
  const length = output.length
  if (length === 0) return ''
  const compact = output.replace(/\s+/g, '')
  if (compact.length >= 2 && compact.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(compact)) {
    return `${(compact.length / 2).toLocaleString('en-US')} B`
  }
  if (
    length >= 16 &&
    /^[A-Za-z0-9+/]+={0,2}$/.test(compact) &&
    /[a-z]/.test(compact) &&
    /[A-Z]/.test(compact) &&
    /\d/.test(compact)
  ) {
    const remainder = length % 4
    const bytes = Math.floor(length / 4) * 3 + (remainder === 2 ? 1 : remainder === 3 ? 2 : 0)
    return `${bytes.toLocaleString('en-US')} B`
  }
  return `${length.toLocaleString('en-US')} chars`
}

/** Screen-reader sentence for a dice roll, per DESIGN §6. */
export function diceAnnouncement(spec: FieldSpec): string {
  switch (spec.generator) {
    case 'hexBytes':
    case 'base64Bytes':
    case 'base64UrlBytes':
      return `Generated ${spec.generatorSize ?? 32} random bytes`
    case 'password':
      return 'Generated a random password'
    case 'textSalt':
      return 'Generated a random salt'
    case 'number':
      return 'Generated a random number'
    case 'defuseKey':
      return 'Generated a defuse key'
    case 'rsaKeyPair':
      return 'Generated an RSA key pair'
    default:
      return 'Generated a random value'
  }
}

/** Display cap for the output card. Copy always copies the full value. */
export const DISPLAY_CAP = 512 * 1024

export function isEditableTarget(target: EventTarget | null): boolean {
  return (
    target instanceof HTMLElement &&
    (target.matches('input, textarea, select') || target.isContentEditable)
  )
}
