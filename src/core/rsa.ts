/** RSA over the platform WebCrypto (subtle) implementation: the one part of
 * the core that needs the webview's native crypto because key generation
 * and PKCS#1 modular arithmetic are not worth re-implementing.
 *
 * PEM keys are algorithm-agnostic on disk, so every PEM import goes through
 * RSASSA-PKCS1-v1_5 and is re-imported as RSA-OAEP through its stripped JWK
 * when an OAEP operation needs it. Node >= 20 and every Tauri webview
 * (WebView2, WKWebView, WebKitGTK) ship subtle with RSA support. */
import { CipherError } from './types'
import { base64, base64Url, unbase64, unbase64Url } from './primitives'

export type RsaBits = 2048 | 3072 | 4096

export interface RsaPemPair {
  pub: string
  priv: string
}

const subtle = (): SubtleCrypto => {
  const c = globalThis.crypto
  if (!c?.subtle) throw new CipherError('This webview has no WebCrypto (crypto.subtle) available.')
  return c.subtle
}

// ---------------------------------------------------------------- pem

export interface PemBody {
  label: string
  der: Uint8Array
}

export function parsePem(pem: string): PemBody {
  const match = pem.match(/-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/)
  if (!match) throw new CipherError('That does not look like a PEM block (missing BEGIN/END lines).')
  const body = match[2].replace(/\s+/g, '')
  if (body.length === 0) throw new CipherError('The PEM block is empty.')
  return { label: match[1], der: unbase64(body) }
}

export function buildPem(label: string, der: Uint8Array): string {
  const b64 = base64(der)
  const lines = b64.match(/.{1,64}/g) ?? []
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`
}

const RSA_OID = '1.2.840.113549.1.1.1'

function derLength(n: number): number[] {
  if (n < 0x80) return [n]
  const bytes: number[] = []
  let v = n
  while (v > 0) {
    bytes.unshift(v & 0xff)
    v >>= 8
  }
  return [0x80 | bytes.length, ...bytes]
}

function derSeq(...parts: number[][]): number[] {
  const body = parts.flat()
  return [0x30, ...derLength(body.length), ...body]
}

/** Wrap a PKCS#1 "RSA PRIVATE KEY" body into a PKCS#8 PRIVATE KEY, the only
 * private format WebCrypto imports. */
function wrapPkcs1ToPkcs8(pkcs1: Uint8Array): Uint8Array {
  const algorithmId = derSeq([0x06, 0x09, ...oidBytes(RSA_OID)], [0x05, 0x00])
  const version = [0x02, 0x01, 0x00]
  const octet = [0x04, ...derLength(pkcs1.length), ...Array.from(pkcs1)]
  return Uint8Array.from(derSeq(version, algorithmId, octet))
}

function oidBytes(oid: string): number[] {
  const parts = oid.split('.').map(Number)
  const out = [parts[0] * 40 + parts[1]]
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i]
    const stack: number[] = [v & 0x7f]
    v >>= 7
    while (v > 0) {
      stack.unshift((v & 0x7f) | 0x80)
      v >>= 7
    }
    out.push(...stack)
  }
  return out
}

export interface ImportedRsaKeys {
  public: CryptoKey
  private: CryptoKey | null
  bits: number
}

const RSASSA_SHA256 = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } as const

/** Import a public and/or private PEM, returning RSASSA keys plus the
 * modulus size. Accepts SPKI, PKCS#8 and legacy PKCS#1 private PEMs. */
export async function importRsaPems(pubPem?: string, privPem?: string): Promise<ImportedRsaKeys> {
  const s = subtle()
  let pubKey: CryptoKey | null = null
  let privKey: CryptoKey | null = null

  const pubText = pubPem?.trim() ?? ''
  if (pubText.length > 0) {
    const { label, der } = parsePem(pubText)
    if (label !== 'PUBLIC KEY')
      throw new CipherError('That does not look like a valid public key in PEM format.')
    try {
      pubKey = await s.importKey('spki', toBuffer(der), RSASSA_SHA256, true, ['verify'])
    } catch {
      throw new CipherError('That does not look like a valid public key in PEM format.')
    }
  }

  const privText = privPem?.trim() ?? ''
  if (privText.length > 0) {
    let { label, der } = parsePem(privText)
    if (label === 'RSA PRIVATE KEY') {
      label = 'PRIVATE KEY'
      der = wrapPkcs1ToPkcs8(der)
    }
    if (label !== 'PRIVATE KEY')
      throw new CipherError('That does not look like a valid private key in PEM format.')
    try {
      privKey = await s.importKey('pkcs8', toBuffer(der), RSASSA_SHA256, true, ['sign'])
    } catch {
      throw new CipherError('That does not look like a valid private key in PEM format.')
    }
  }

  if (!pubKey && !privKey) throw new CipherError('No RSA key material was provided.')
  const jwk = await s.exportKey('jwk', (pubKey ?? privKey) as CryptoKey)
  const bits = modulusBits(jwk.n ?? '')
  const resolvedPublic = pubKey ?? (await derivePublicFromPrivate(privKey as CryptoKey))
  return { public: resolvedPublic, private: privKey, bits }
}

async function derivePublicFromPrivate(priv: CryptoKey): Promise<CryptoKey> {
  const s = subtle()
  const jwk = await s.exportKey('jwk', priv)
  return s.importKey(
    'jwk',
    { kty: jwk.kty, n: jwk.n, e: jwk.e },
    RSASSA_SHA256,
    true,
    ['verify']
  )
}

export function modulusBits(nB64Url: string): number {
  const bytes = unbase64Url(nB64Url)
  let i = 0
  while (i < bytes.length && bytes[i] === 0) i++
  return (bytes.length - i) * 8
}

// -------------------------------------------------------------- jwk

/** Export a CryptoKey's JWK with the alg/use/key_ops markers stripped so it
 * can be re-imported under a different RSA algorithm (OAEP vs RSASSA). */
async function bareJwk(key: CryptoKey): Promise<JsonWebKey> {
  const jwk = await subtle().exportKey('jwk', key)
  const bare: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(jwk)) if (!['alg', 'use', 'key_ops'].includes(k)) bare[k] = v
  return bare as JsonWebKey
}

// ------------------------------------------------------------ oaep

const OAEP_SHA256 = { name: 'RSA-OAEP', hash: 'SHA-256' } as const

async function oaepKey(key: CryptoKey, decrypt: boolean): Promise<CryptoKey> {
  const jwk = await bareJwk(key)
  return subtle().importKey('jwk', jwk, OAEP_SHA256, false, decrypt ? ['decrypt'] : ['encrypt'])
}

export async function oaepEncrypt(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const enc = await oaepKey(key, false)
  return new Uint8Array(await subtle().encrypt(OAEP_SHA256, enc, toBuffer(data)))
}

export async function oaepDecrypt(key: CryptoKey, ciphertext: Uint8Array): Promise<Uint8Array> {
  const dec = await oaepKey(key, true)
  return new Uint8Array(await subtle().decrypt(OAEP_SHA256, dec, toBuffer(ciphertext)))
}

// ----------------------------------------------------------- rsassa

export type RsHash = 'SHA-256' | 'SHA-384' | 'SHA-512'

export async function rsassaSign(
  priv: CryptoKey,
  data: Uint8Array,
  hash: RsHash
): Promise<Uint8Array> {
  const s = subtle()
  const jwk = await bareJwk(priv)
  const key = await s.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['sign'])
  return new Uint8Array(await s.sign('RSASSA-PKCS1-v1_5', key, toBuffer(data)))
}

export async function rsassaVerify(
  pub: CryptoKey,
  signature: Uint8Array,
  data: Uint8Array,
  hash: RsHash
): Promise<boolean> {
  const s = subtle()
  const jwk = await bareJwk(pub)
  const key = await s.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['verify'])
  return s.verify('RSASSA-PKCS1-v1_5', key, toBuffer(signature), toBuffer(data))
}

// --------------------------------------------------------- generate

export async function generateRsaPemPair(bits: RsaBits): Promise<RsaPemPair> {
  const s = subtle()
  const pair = await s.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: bits,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify']
  )
  const spki = new Uint8Array(await s.exportKey('spki', pair.publicKey))
  const pkcs8 = new Uint8Array(await s.exportKey('pkcs8', pair.privateKey))
  return { pub: buildPem('PUBLIC KEY', spki), priv: buildPem('PRIVATE KEY', pkcs8) }
}

// -------------------------------------------------------------- jwks

export interface RsaJwkFields {
  n: string
  e: string
  d?: string
  p?: string
  q?: string
  dp?: string
  dq?: string
  qi?: string
}

export async function jwkFromPem(pem: string, expectPrivate: boolean): Promise<RsaJwkFields> {
  const keys = await importRsaPems(undefined, pem)
  if (expectPrivate && !keys.private)
    throw new CipherError('That does not look like a valid private key in PEM format.')
  const jwk = await subtle().exportKey('jwk', keys.private ?? keys.public)
  return jwk as RsaJwkFields
}

export async function jwkToRsaKeys(jwk: RsaJwkFields): Promise<{ public: CryptoKey; private: CryptoKey | null; bits: number }> {
  const s = subtle()
  const strip = (v: string) => {
    const bytes = unbase64Url(v)
    let i = 0
    while (i < bytes.length && bytes[i] === 0) i++
    return base64Url(bytes.subarray(i))
  }
  const pubJwk = { kty: 'RSA', n: strip(jwk.n), e: strip(jwk.e) }
  let pub: CryptoKey
  try {
    pub = await s.importKey('jwk', pubJwk, RSASSA_SHA256, true, ['verify'])
  } catch {
    throw new CipherError('The JWK numbers do not form a valid RSA key.')
  }
  let priv: CryptoKey | null = null
  if (jwk.d) {
    try {
      priv = await s.importKey(
        'jwk',
        {
          kty: 'RSA',
          n: pubJwk.n,
          e: pubJwk.e,
          d: strip(jwk.d),
          p: strip(jwk.p ?? ''),
          q: strip(jwk.q ?? ''),
          dp: strip(jwk.dp ?? ''),
          dq: strip(jwk.dq ?? ''),
          qi: strip(jwk.qi ?? ''),
        },
        RSASSA_SHA256,
        true,
        ['sign']
      )
    } catch {
      throw new CipherError('The JWK numbers do not form a valid RSA key.')
    }
  }
  return { public: pub, private: priv, bits: modulusBits(jwk.n) }
}

// ------------------------------------------------------------- misc

function toBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer
}
