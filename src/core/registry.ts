/** Every cipher method the app knows, in display order. Ported from the
 * C# Registry. */
import { CipherError, type CipherMethod, type FieldSpec } from './types'
import { encodingMethods } from './encoding'
import { classicalMethods } from './classical'
import { hashMethods } from './hash'
import { modernMethods } from './modern'
import { defuseMethods } from './defuseMethods'
import { tokenMethods } from './tokens'
import { newKeyAscii } from './defuse'
import {
  randomHex,
  randomBase64,
  randomBase64Url,
  randomPassword,
  randomToken,
  randomInt,
} from './primitives'

export const registry: readonly CipherMethod[] = [
  ...encodingMethods,
  ...classicalMethods,
  ...hashMethods,
  ...modernMethods,
  ...defuseMethods,
  ...tokenMethods,
]

export const CATEGORY_ORDER: readonly string[] = [
  'Encoding',
  'Classical',
  'Hash',
  'Modern',
  'Defuse PHP',
  'Tokens',
]

export function findMethod(idOrName: string): CipherMethod | undefined {
  const needle = idOrName.toLowerCase()
  return registry.find(
    (m) => m.id.toLowerCase() === needle || m.name.toLowerCase() === needle
  )
}

/** Search across name, aliases and category, the fuel for the
 * type-to-filter selector. */
export function searchMethods(text: string): readonly CipherMethod[] {
  const q = text.trim()
  if (q.length === 0) return registry
  const terms = q.toLowerCase().split(/\s+/).filter((t) => t.length > 0)
  return registry.filter((m) => {
    const haystack = [m.name, m.id, m.category, ...m.aliases].map((s) => s.toLowerCase())
    return terms.every((t) => haystack.some((h) => h.includes(t)))
  })
}

/** The default dice-button dispatch for the simple generator kinds; RSA
 * pairs and defuse keys are handled at the source. */
export async function defaultGenerate(
  spec: FieldSpec,
  field: string
): Promise<Record<string, string>> {
  const size = spec.generatorSize ?? 32
  switch (spec.generator) {
    case 'hexBytes':
      return { [field]: randomHex(size) }
    case 'base64Bytes':
      return { [field]: randomBase64(size) }
    case 'base64UrlBytes':
      return { [field]: randomBase64Url(size) }
    case 'password':
      return { [field]: randomPassword(size) }
    case 'textSalt':
      return { [field]: randomToken(size) }
    case 'defuseKey':
      return { [field]: newKeyAscii() }
    case 'number': {
      const [min, max] = spec.generatorRange ?? [1, 10]
      return { [field]: String(randomInt(min, max + 1)) }
    }
    default:
      throw new CipherError(`No generator for ${field}.`)
  }
}

/** Generate values for a field, routing to the method's own generator
 * (RSA pairs) when it has one. */
export async function generateForField(
  method: CipherMethod,
  field: string,
  current: Readonly<Record<string, string>>
): Promise<Record<string, string>> {
  const spec = method.fields.find((f) => f.name === field)
  if (!spec) throw new CipherError(`No generator for ${field}.`)
  if (method.generate) return method.generate(field, current)
  if (!spec.generator) throw new CipherError(`No generator for ${field}.`)
  if (spec.generator === 'rsaKeyPair')
    throw new CipherError(`No generator for ${field}.`)
  return defaultGenerate(spec, field)
}
