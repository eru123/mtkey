/** The Tokens methods: JWT sign/decode/verify and JWKS build/inspect.
 * Ported from the C# Methods_Tokens with the explainer copy intact.
 * HMAC paths use @noble/hashes, RSA paths use WebCrypto via rsa.ts. */
import { hmac } from '@noble/hashes/hmac.js'
import { sha256Hash, sha384Hash, sha512Hash } from './noble'
import {
  CipherError,
  defineMethod,
  field,
  type CipherMethod,
  type CipherResult,
} from './types'
import {
  base64Url,
  unbase64Url,
  utf8Encode,
  utf8Decode,
  randomHex,
} from './primitives'
import {
  generateRsaPemPair,
  importRsaPems,
  rsassaSign,
  rsassaVerify,
  jwkFromPem,
  jwkToRsaKeys,
  type RsaBits,
  type RsHash,
} from './rsa'

const JWT_ALGS = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'] as const
type JwtAlg = (typeof JWT_ALGS)[number]

export const jwtMethod: CipherMethod = defineMethod({
  id: 'jwt',
  name: 'JWT',
  category: 'Tokens',
  blurb: 'JSON Web Tokens: sign a payload, or crack one open and check its signature.',
  learn:
    'A JWT is three base64url chunks joined by dots: header.payload.signature. The ' +
    'header names the algorithm, the payload carries claims (sub, exp, iat, roles), and ' +
    'the signature is an HMAC (HS256, shared secret) or an RSA signature (RS256, private ' +
    'key signs, public key verifies). Two things people get wrong constantly: a JWT is ' +
    'encoded, not encrypted, anyone can read the payload; and never trust alg from the ' +
    "token itself when verifying, attackers edit it to 'none'. Decode here shows all " +
    'three parts and checks expiry claims for you.',
  wikiUrl: 'https://en.wikipedia.org/wiki/JSON_Web_Token',
  aliases: ['json web token', 'bearer'],
  encodeLabel: 'Sign',
  decodeLabel: 'Decode & verify',
  fields: [
    {
      name: 'alg',
      label: 'Algorithm',
      kind: 'dropdown',
      options: JWT_ALGS,
      default: 'HS256',
      hint: 'HS* = shared secret. RS* = RSA keys. Must match the key you provide.',
    },
    {
      name: 'secret',
      label: 'HMAC secret',
      secret: true,
      placeholder: 'your-256-bit-secret',
      hint: 'Only for HS256/384/512.',
      generator: 'base64UrlBytes',
      generatorSize: 32,
    },
    {
      name: 'priv',
      label: 'RSA private key (PEM)',
      kind: 'multiline',
      secret: true,
      placeholder: '-----BEGIN PRIVATE KEY-----',
      hint: 'Signs RS* tokens.',
      generator: 'rsaKeyPair',
    },
    {
      name: 'pub',
      label: 'RSA public key (PEM)',
      kind: 'multiline',
      placeholder: '-----BEGIN PUBLIC KEY-----',
      hint: 'Verifies RS* tokens.',
      generator: 'rsaKeyPair',
    },
  ],
  process: async (r): Promise<CipherResult> => (r.direction === 'encode' ? jwtSign(r) : jwtDecode(r)),
  generate: async (f, current) => {
    if (f !== 'pub' && f !== 'priv') throw new CipherError(`No generator for ${f}.`)
    return toRecord(await generateRsaPemPair(await parseBits(current['bits'])))
  },
})

/** Widen the PEM pair to the plain record the registry contract expects. */
function toRecord(pair: { pub: string; priv: string }): Record<string, string> {
  return { pub: pair.pub, priv: pair.priv }
}

async function parseBits(value: string | undefined): Promise<RsaBits> {
  const bits = Number.parseInt(value ?? '2048', 10)
  return (bits === 3072 || bits === 4096 ? bits : 2048) as RsaBits
}

async function jwtSign(r: Parameters<CipherMethod['process']>[0]): Promise<CipherResult> {
  const alg = field(r, 'alg') as JwtAlg
  if (!JWT_ALGS.includes(alg)) throw new CipherError('Pick one of the listed algorithms.')

  let payload = r.input.trim()
  if (payload.length > 0) {
    try {
      const parsed: unknown = JSON.parse(payload)
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed))
        throw new CipherError('The payload must be a JSON object, { ... }.')
    } catch (e) {
      if (e instanceof CipherError) throw e
      throw new CipherError('The payload is not valid JSON.')
    }
  } else {
    payload = '{}'
  }

  const header = `{"alg":"${alg}","typ":"JWT"}`
  const signingInput =
    base64Url(utf8Encode(header)) + '.' + base64Url(utf8Encode(payload))
  const sig = await signBytes(alg, utf8Encode(field(r, 'secret')), field(r, 'priv'), utf8Encode(signingInput))
  return {
    output: signingInput + '.' + base64Url(sig),
    note: `Signed with ${alg}. Remember: the payload is readable by anyone.`,
  }
}

async function signBytes(
  alg: JwtAlg,
  secret: Uint8Array,
  privPem: string,
  signingInput: Uint8Array
): Promise<Uint8Array> {
  if (alg.startsWith('HS')) {
    if (secret.length === 0)
      throw new CipherError('HS algorithms need the HMAC secret. The dice rolls a strong one.')
    const hash = alg === 'HS256' ? sha256Hash : alg === 'HS384' ? sha384Hash : sha512Hash
    return hmac(hash, secret, signingInput)
  }

  const priv = privPem.trim()
  if (priv.length === 0)
    throw new CipherError(`${alg} needs the RSA private key to sign. Dice generates a pair.`)
  const keys = await importRsaPems(undefined, priv)
  const hash: RsHash = alg === 'RS384' ? 'SHA-384' : alg === 'RS512' ? 'SHA-512' : 'SHA-256'
  return rsassaSign(keys.private as CryptoKey, signingInput, hash)
}

async function jwtDecode(r: Parameters<CipherMethod['process']>[0]): Promise<CipherResult> {
  const token = r.input.trim()
  const parts = token.split('.')
  if (parts.length < 2 || parts.length > 3)
    throw new CipherError('A JWT looks like header.payload.signature, two dots.')

  const headerJson = prettyJson(decodeSegment(parts[0], 'header'))
  const payloadJson = prettyJson(decodeSegment(parts[1], 'payload'))

  let alg = 'none'
  try {
    const header: unknown = JSON.parse(decodeSegment(parts[0], 'header'))
    if (typeof header === 'object' && header !== null && 'alg' in header)
      alg = String((header as { alg?: unknown }).alg ?? 'none')
  } catch {
    throw new CipherError('The header is not valid JSON.')
  }

  const text =
    `Header:\n${headerJson}\n\n` +
    `Payload:\n${payloadJson}`

  const notes: string[] = [`Token algorithm: ${alg}`]

  if (parts.length === 2 || parts[2].length === 0) {
    notes.push('This token is UNSIGNED (alg none / empty signature). Anyone could have written it.')
  } else if (alg === 'none') {
    notes.push("Header says 'none' but a signature is attached. That mismatch is suspicious.")
  } else {
    const verified = await jwtVerify(token, parts, alg as JwtAlg, r)
    if (!verified) {
      notes.push('Signature does NOT check out. The token was modified or the key is wrong.')
      return {
        output: text,
        note: notes.join('  |  '),
        warning: 'Signature verification failed.',
      }
    }
    notes.push('Signature checks out against the key you provided.')
  }

  const claimNote = describeClaims(parts[1])
  if (claimNote) notes.push(claimNote)

  return { output: text, note: notes.join('  |  ') }
}

async function jwtVerify(
  _token: string,
  parts: string[],
  alg: JwtAlg,
  r: Parameters<CipherMethod['process']>[0]
): Promise<boolean> {
  const signingInput = utf8Encode(parts[0] + '.' + parts[1])
  const sig = unbase64Url(parts[2])

  if (alg.startsWith('HS')) {
    const secret = utf8Encode(field(r, 'secret'))
    if (secret.length === 0)
      throw new CipherError('Provide the HMAC secret to verify an HS* token.')
    const hash = alg === 'HS256' ? sha256Hash : alg === 'HS384' ? sha384Hash : sha512Hash
    const expected = hmac(hash, secret, signingInput)
    if (expected.length !== sig.length) return false
    let diff = 0
    for (let i = 0; i < expected.length; i++) diff |= expected[i] ^ sig[i]
    return diff === 0
  }

  if (!alg.startsWith('RS')) throw new CipherError(`Verifying ${alg} tokens is not supported here.`)

  const pub = field(r, 'pub').trim()
  const priv = field(r, 'priv').trim()
  let keys: Awaited<ReturnType<typeof importRsaPems>>
  if (pub.length > 0) keys = await importRsaPems(pub, undefined)
  else if (priv.length > 0) keys = await importRsaPems(undefined, priv)
  else throw new CipherError('Provide the RSA public key (or the private key) to verify.')
  const hash: RsHash = alg === 'RS384' ? 'SHA-384' : alg === 'RS512' ? 'SHA-512' : 'SHA-256'
  return rsassaVerify(keys.public, sig, signingInput, hash)
}

function decodeSegment(segment: string, what: string): string {
  try {
    return utf8Decode(unbase64Url(segment))
  } catch (e) {
    throw new CipherError(
      `The ${what} segment is not valid base64url. ${e instanceof Error ? e.message : ''}`
    )
  }
}

function describeClaims(payloadSegment: string): string | null {
  try {
    const payload: unknown = JSON.parse(decodeSegment(payloadSegment, 'payload'))
    if (typeof payload !== 'object' || payload === null) return null
    const now = Math.floor(Date.now() / 1000)
    const notes: string[] = []
    const claims = payload as Record<string, unknown>

    if (typeof claims['exp'] === 'number') {
      const exp = claims['exp']
      notes.push(
        exp < now
          ? `Expired ${Math.floor((now - exp) / 60)} minutes ago`
          : `Valid for another ${Math.floor((exp - now) / 60)} minutes`
      )
    }
    if (typeof claims['nbf'] === 'number' && claims['nbf'] > now)
      notes.push(`Not valid yet, starts in ${Math.floor((claims['nbf'] - now) / 60)} minutes`)
    if (typeof claims['iat'] === 'number')
      notes.push(`Issued ${Math.floor((now - claims['iat']) / 60)} minutes ago`)
    return notes.length > 0 ? notes.join(', ') : null
  } catch {
    return 'Payload claims could not be read (not JSON).'
  }
}

export function prettyJson(json: string): string {
  const parsed: unknown = JSON.parse(json)
  return JSON.stringify(parsed, null, 2)
}

// -------------------------------------------------------------- jwks

export const jwksMethod: CipherMethod = defineMethod({
  id: 'jwks',
  name: 'JWKS',
  category: 'Tokens',
  blurb: 'JSON Web Key Set: publish verification keys as JSON, or inspect one.',
  learn:
    'A JWKS is the standard way services publish their public keys: {' +
    '"keys":[...]} where each JWK describes a key with fields like kty (key type), ' +
    'kid (key id), n and e (an RSA modulus and exponent in base64url). Auth servers ' +
    'expose a JWKS endpoint so anyone can verify their JWTs without shipping PEM files. ' +
    'Encode mints a key set from your RSA key (or a fresh one). Decode inspects a JWKS ' +
    'and hands you the PEM form of each RSA key it finds.',
  wikiUrl: 'https://en.wikipedia.org/wiki/JSON_Web_Key',
  aliases: ['json web key', 'jwk'],
  encodeLabel: 'Build key set',
  decodeLabel: 'Inspect',
  fields: [
    {
      name: 'priv',
      label: 'RSA private key (PEM)',
      kind: 'multiline',
      secret: true,
      placeholder: 'leave empty to mint a fresh 2048-bit key',
      hint: 'Empty + Encode = new keypair. The private parts go into the JWK.',
      generator: 'rsaKeyPair',
    },
    {
      name: 'kid',
      label: 'Key ID (kid)',
      placeholder: 'auto: 8 random hex chars',
      hint: 'Tokens reference the key they were signed with by this id.',
      generator: 'textSalt',
      generatorSize: 8,
    },
  ],
  process: async (r): Promise<CipherResult> => {
    if (r.direction === 'encode') {
      const privPem = field(r, 'priv').trim()
      let minted = false
      let pair: { pub: string; priv: string }
      if (privPem.length > 0) {
        await importRsaPems(undefined, privPem) // validates the PEM up front
        pair = { pub: '', priv: privPem }
      } else {
        pair = await generateRsaPemPair(2048)
        minted = true
      }

      let kid = field(r, 'kid').trim()
      if (kid.length === 0) kid = randomHex(4)

      const jwkFields = await jwkFromPem(pair.priv, true)
      const jwk = rsaToJwkJson(jwkFields, kid)
      const jwks = `{"keys":[${jwk}]}`
      return {
        output: prettyJson(jwks),
        note: minted
          ? `Minted a fresh RSA-2048 key with kid '${kid}'.`
          : `Built from your key, kid '${kid}'.`,
      }
    }

    return jwksInspect(r.input)
  },
  generate: async (f, current) => {
    if (f !== 'pub' && f !== 'priv') throw new CipherError(`No generator for ${f}.`)
    return toRecord(await generateRsaPemPair(await parseBits(current['bits'])))
  },
})

function rsaToJwkJson(fields: { n: string; e: string; d?: string; p?: string; q?: string; dp?: string; dq?: string; qi?: string }, kid: string): string {
  let j = `{"kty":"RSA"`
  if (kid.length > 0) j += `,"kid":"${kid}"`
  j += ',"use":"sig"'
  // RS256 is the usual pairing for verification keys; the hash choice is
  // independent of the key size, so we do not pretend otherwise.
  j += ',"alg":"RS256"'
  j += `,"n":"${fields.n}"`
  j += `,"e":"${fields.e}"`
  if (fields.d) {
    j += `,"d":"${fields.d}"`
    j += `,"p":"${fields.p ?? ''}"`
    j += `,"q":"${fields.q ?? ''}"`
    j += `,"dp":"${fields.dp ?? ''}"`
    j += `,"dq":"${fields.dq ?? ''}"`
    j += `,"qi":"${fields.qi ?? ''}"`
  }
  return j + '}'
}

async function jwksInspect(input: string): Promise<CipherResult> {
  let keysRoot: unknown
  try {
    const root: unknown = JSON.parse(input.trim())
    if (Array.isArray(root)) keysRoot = root
    else if (typeof root === 'object' && root !== null && 'keys' in root)
      keysRoot = (root as { keys: unknown }).keys
    else
      throw new CipherError('This is neither a key set {"keys":[...]} nor an array of JWKs.')
  } catch (e) {
    if (e instanceof CipherError) throw e
    throw new CipherError('The input is not valid JSON.')
  }

  if (!Array.isArray(keysRoot) || keysRoot.length === 0)
    throw new CipherError('The key set contains no keys.')

  const lines: string[] = []
  let index = 0
  for (const key of keysRoot) {
    index++
    const jwk = (typeof key === 'object' && key !== null ? key : {}) as Record<string, unknown>
    const kty = typeof jwk['kty'] === 'string' ? jwk['kty'] : '?'
    const kid = typeof jwk['kid'] === 'string' ? jwk['kid'] : ''
    const use = typeof jwk['use'] === 'string' ? jwk['use'] : ''
    const alg = typeof jwk['alg'] === 'string' ? jwk['alg'] : ''

    lines.push(
      `Key ${index}: kty=${kty}` +
        (kid.length > 0 ? `, kid=${kid}` : '') +
        (use.length > 0 ? `, use=${use}` : '') +
        (alg.length > 0 ? `, alg=${alg}` : '')
    )

    if (kty === 'RSA') {
      try {
        const imported = await jwkToRsaKeys(jwk as unknown as Parameters<typeof jwkToRsaKeys>[0])
        const hasPrivate = 'd' in jwk
        lines.push(`  Size: ${imported.bits}-bit${hasPrivate ? ' (private material present)' : ''}`)
        const pair = await importedToPems(imported)
        lines.push('  Public PEM:')
        lines.push(pair.pub.trimEnd())
        if (hasPrivate) {
          lines.push('  Private PEM:')
          lines.push(pair.priv.trimEnd())
        }
      } catch (e) {
        lines.push(`  Could not reconstruct the key: ${e instanceof Error ? e.message : String(e)}`)
      }
    } else if (kty === 'EC' || kty === 'OKP') {
      lines.push('  Elliptic-curve key: sizes and PEM export for EC/OKP are not supported here.')
    }
    lines.push('')
  }
  return {
    output: lines.join('\n').trimEnd(),
    note: `${keysRoot.length} key(s) found.`,
  }
}

async function importedToPems(imported: Awaited<ReturnType<typeof jwkToRsaKeys>>): Promise<{ pub: string; priv: string }> {
  const { buildPem } = await import('./rsa')
  const s = globalThis.crypto.subtle
  const spki = new Uint8Array(await s.exportKey('spki', imported.public))
  const pub = buildPem('PUBLIC KEY', spki)
  let priv = ''
  if (imported.private) {
    const pkcs8 = new Uint8Array(await s.exportKey('pkcs8', imported.private))
    priv = buildPem('PRIVATE KEY', pkcs8)
  }
  return { pub, priv }
}

export const tokenMethods: readonly CipherMethod[] = [jwtMethod, jwksMethod]
