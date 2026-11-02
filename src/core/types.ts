/** The method registry contract, ported from the C# Mtkey.Core model.
 * Everything the UI needs to render a method lives in these types. */

export type Direction = 'encode' | 'decode'

export type Category =
  | 'Encoding'
  | 'Classical'
  | 'Hash'
  | 'Modern'
  | 'PHP Interop'
  | 'Tokens'

export type FieldKind = 'text' | 'multiline' | 'dropdown' | 'number'

/** What the dice button next to a field should produce. */
export type GeneratorKind =
  | 'hexBytes'
  | 'base64Bytes'
  | 'base64UrlBytes'
  | 'password'
  | 'textSalt'
  | 'number'
  | 'defuseKey'
  | 'rsaKeyPair'

export interface FieldSpec {
  name: string
  label: string
  kind?: FieldKind
  placeholder?: string
  options?: readonly string[]
  default?: string
  min?: number
  max?: number
  /** Field content is a secret, so the UI masks it. */
  secret?: boolean
  /** Small grey hint shown under the label. */
  hint?: string
  generator?: GeneratorKind
  /** Byte count for the byte-based generators. */
  generatorSize?: number
  /** Inclusive range for the number generator. */
  generatorRange?: readonly [number, number]
}

export interface CipherRequest {
  direction: Direction
  input: string
  fields: Readonly<Record<string, string>>
}

export interface CipherResult {
  output: string
  note?: string
  warning?: string
}

/** A user-facing failure with a friendly sentence, shown in the error area. */
export class CipherError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CipherError'
  }
}

export interface Validation {
  ok: boolean
  message: string
  certain: boolean
}

export const validation = {
  unknown: (): Validation => ({ ok: true, message: '', certain: false }),
  good: (message: string): Validation => ({ ok: true, message, certain: true }),
  bad: (message: string): Validation => ({ ok: false, message, certain: true }),
}

export interface FieldValidation {
  fields: Record<string, Validation>
  overall: string
}

export const emptyValidation = (): FieldValidation => ({ fields: {}, overall: '' })

export interface CipherMethod {
  readonly id: string
  readonly name: string
  readonly category: Category
  /** One-liner shown under the selector. */
  readonly blurb: string
  /** Longer classroom-style explanation shown in the info area. */
  readonly learn: string
  readonly wikiUrl: string
  /** False for one-way functions, then only Encode is offered. */
  readonly twoWay: boolean
  readonly encodeLabel: string
  readonly decodeLabel: string
  /** Extra search terms so "b64" finds Base64 and "sha2" finds SHA-256. */
  readonly aliases: readonly string[]
  readonly fields: readonly FieldSpec[]
  process(request: CipherRequest): Promise<CipherResult>
  /** Live validation of key material and other fields as the user types. */
  validateFields?(values: Readonly<Record<string, string>>): Promise<FieldValidation>
  /** Values produced by the dice button. May fill several fields at once
   * (an RSA key pair, for example, is born together). */
  generate?(field: string, current: Readonly<Record<string, string>>): Promise<Record<string, string>>
}

type MethodInput = Omit<
  CipherMethod,
  'twoWay' | 'encodeLabel' | 'decodeLabel' | 'aliases' | 'fields' | 'learn'
> &
  Partial<Pick<CipherMethod, 'twoWay' | 'encodeLabel' | 'decodeLabel' | 'aliases' | 'fields' | 'learn'>>

/** Fill in the defaults every method shares. */
export function defineMethod(m: MethodInput): CipherMethod {
  return {
    twoWay: true,
    encodeLabel: 'Encode',
    decodeLabel: 'Decode',
    aliases: [],
    fields: [],
    ...m,
    learn: m.learn ?? m.blurb,
  }
}

/** Read a field with the C# `Field()` semantics: missing key reads as "". */
export function field(request: CipherRequest, name: string): string {
  return request.fields[name] ?? ''
}
