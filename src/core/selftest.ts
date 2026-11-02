/** Known-answer tests and roundtrips, ported from the C# SelfTest and run
 * by `pnpm test`, the in-app self-test view and CI. Defuse cross-language
 * vectors come from tools/gen-vectors.php, which produces them with the
 * real PHP library. */
import vectorsJson from '../../tests/vectors.json'
import mcryptVectorsJson from '../../tests/mcrypt-vectors.json'
import type { CipherRequest, CipherMethod, Direction } from './types'
import { findMethod } from './registry'
import * as P from './primitives'
import * as D from './defuse'
import { generateRsaPemPair } from './rsa'
import { md5Hash, sha512Hash } from './noble'

export interface TestCase {
  name: string
  pass: boolean
  detail?: string
}

interface DefuseVectors {
  v2_key?: { key_ascii: string; plaintext: string; ciphertext_hex: string }
  v2_password?: { password: string; plaintext: string; ciphertext_hex: string }
  v2_kat?: {
    key_hex: string
    salt_hex: string
    iv_hex: string
    plaintext: string
    ciphertext_hex: string
  }
  v2_password_kat?: {
    password: string
    salt_hex: string
    iv_hex: string
    plaintext: string
    ciphertext_hex: string
  }
  key_wrap?: { password: string; protected_key_ascii: string; inner_key_ascii: string }
  legacy_kat?: { key_hex: string; plaintext: string; ciphertext_hex: string }
}

const vectors = vectorsJson as DefuseVectors

async function run(
  method: CipherMethod,
  direction: Direction,
  input: string,
  fields: Record<string, string> = {}
) {
  return method.process({ direction, input, fields } satisfies CipherRequest)
}

export async function runSelfTest(): Promise<TestCase[]> {
  const cases: TestCase[] = []
  const check = (name: string, pass: boolean, detail?: string) =>
    cases.push(pass ? { name, pass } : { name, pass, detail })

  // ------------------------------------------------------ digests
  check(
    'md5(abc) known answer',
    P.hex(md5Hash(P.utf8Encode('abc'))) === '900150983cd24fb0d6963f7d28e17f72'
  )
  check(
    'sha256(abc) known answer',
    P.hex(P.sha256(P.utf8Encode('abc'))) ===
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
  )
  check(
    'sha512(abc) known answer',
    P.hex(sha512Hash(P.utf8Encode('abc'))).startsWith(
      'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a'
    )
  )
  check(
    'crc32(quick brown fox) known answer',
    P.crc32(P.utf8Encode('The quick brown fox jumps over the lazy dog')) === 0x414fa339
  )

  // RFC 4231 test case 2
  const hmacVector = P.hmacSha256(P.utf8Encode('Jefe'), P.utf8Encode('what do ya want for nothing?'))
  check(
    'hmac-sha256 RFC 4231 vector',
    P.hex(hmacVector) === '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'
  )

  // RFC 7914 section 11
  const pbkdf2Vector = P.pbkdf2Sha256(P.utf8Encode('password'), P.utf8Encode('salt'), 1, 32)
  check(
    'pbkdf2-sha256 RFC 7914 vector',
    P.hex(pbkdf2Vector) === '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b'
  )

  // RFC 5869 test case 1
  const ikm = new Uint8Array(22).fill(0x0b)
  const okm = P.hkdfSha256(
    ikm,
    P.unhex('000102030405060708090a0b0c'),
    Uint8Array.from([0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9]),
    42
  )
  check(
    'hkdf-sha256 RFC 5869 vector',
    P.hex(okm) ===
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'
  )

  // ---------------------------------------------------- encodings
  check('base64 RFC 4648 vector', P.base64(P.utf8Encode('foobar')) === 'Zm9vYmFy')
  check('base32 RFC 4648 vector', P.base32(P.utf8Encode('foobar')) === 'MZXW6YTBOI')
  check(
    'base58 roundtrip incl. leading zeros',
    P.utf8Decode(P.unbase58(P.base58(P.utf8Encode('\0\0attack at dawn\0')))) === '\0\0attack at dawn\0'
  )
  check(
    'base58 edge cases',
    P.base58(new Uint8Array([0])) === '1' &&
      P.base58(new Uint8Array([0, 1])) === '12' &&
      ((a, b) => a.length === b.length && a.every((v, i) => v === b[i]))(
        Array.from(P.unbase58('1')),
        [0]
      )
  )
  check(
    'url encoding',
    (await import('./encoding')).percentEncode('a b&c') === 'a%20b%26c'
  )
  check(
    'binary bits',
    P.toBinary(P.utf8Encode('Hi')) === '01001000 01101001' &&
      P.utf8Decode(P.fromBinary('01001000 01101001')) === 'Hi'
  )
  check(
    'morse SOS',
    (await run((await import('./encoding')).morseMethod, 'encode', 'SOS')).output === '... --- ...'
  )

  // ---------------------------------------------------- classical
  const { caesarMethod, rot13Method, atbashMethod, vigenereMethod, railFenceMethod, xorMethod, playfairMethod } =
    await import('./classical')
  check(
    'caesar shift 3',
    (await run(caesarMethod, 'encode', 'Caesar, 42!', { shift: '3' })).output === 'Fdhvdu, 42!'
  )
  check('rot13', (await run(rot13Method, 'encode', 'Hello')).output === 'Uryyb')
  check('atbash', (await run(atbashMethod, 'encode', 'HELLO')).output === 'SVOOL')
  check(
    'vigenere textbook vector',
    (await run(vigenereMethod, 'encode', 'ATTACKATDAWN', { key: 'LEMON' })).output === 'LXFOPVEFRNHR'
  )
  check(
    'rail fence 3 rails',
    (await run(railFenceMethod, 'encode', 'WEAREDISCOVEREDFLEEATONCE', { rails: '3' })).output
      .replace(/ /g, '') === 'WECRLTEERDSOEEFEAOCAIVDEN'
  )
  check(
    'playfair wikipedia example',
    (
      await run(playfairMethod, 'encode', 'Hide the gold in the tree stump', {
        key: 'playfair example',
      })
    ).output.replace(/ /g, '') === 'BMODZBXDNABEKUDMUIXMMOUVIF'
  )
  check(
    'xor roundtrip',
    (await run(xorMethod, 'decode', (await run(xorMethod, 'encode', 'attack at dawn', { key: 'secret' })).output, { key: 'secret' }))
      .output === 'attack at dawn'
  )

  // -------------------------------------------------------- modern
  const { rsaMethod, rsaSignMethod } = await import('./modern')
  const rsaPair = await generateRsaPemPair(2048)
  const rsaRequest = { pub: rsaPair.pub, priv: rsaPair.priv }
  const rsaSecret = await rsaMethod.process({
    direction: 'encode',
    input: 'small secret',
    fields: rsaRequest,
  })
  const rsaBack = await rsaMethod.process({
    direction: 'decode',
    input: rsaSecret.output,
    fields: rsaRequest,
  })
  check('rsa keypair roundtrip', rsaBack.output === 'small secret')

  const pairValidation = await rsaMethod.validateFields?.(rsaRequest)
  check(
    'rsa pair validation accepts',
    (pairValidation?.overall ?? '').includes('verified'),
    pairValidation?.overall
  )

  const other = await generateRsaPemPair(2048)
  const mismatch = await rsaMethod.validateFields?.({ pub: other.pub, priv: rsaPair.priv })
  check(
    'rsa pair validation rejects mismatch',
    (mismatch?.overall ?? '').includes('NOT belong'),
    mismatch?.overall
  )

  const signResult = await rsaSignMethod.process({
    direction: 'encode',
    input: 'the message',
    fields: rsaRequest,
  })
  const verify = await rsaSignMethod.process({
    direction: 'decode',
    input: 'the message',
    fields: { ...rsaRequest, sig: signResult.output },
  })
  check('rsa sign/verify', verify.output.includes('VALID'))
  let tampered = false
  try {
    await rsaSignMethod.process({
      direction: 'decode',
      input: 'the message!',
      fields: { ...rsaRequest, sig: signResult.output },
    })
  } catch {
    tampered = true
  }
  check('rsa sign detects tampering', tampered)

  const blockFields = {
    key: '32bytesofpuregoldenkeymaterial!!',
    keyenc: 'Text (UTF-8)',
    iv: '0123456789abcdef',
    ivenc: 'Text (UTF-8)',
    out: 'Base64',
  }
  const cbcEnc = await findMethod('aes-cbc')!.process({
    direction: 'encode',
    input: 'two way street \ud83d\udea6',
    fields: blockFields,
  })
  const cbcDec = await findMethod('aes-cbc')!.process({
    direction: 'decode',
    input: cbcEnc.output,
    fields: blockFields,
  })
  check('aes-cbc roundtrip', cbcDec.output === 'two way street \ud83d\udea6')

  const gcmFields = {
    key: '16bytesofpurekey',
    keyenc: 'Text (UTF-8)',
    iv: 'nonce1234567',
    ivenc: 'Text (UTF-8)',
    out: 'Base64',
  }
  const gcm = findMethod('aes-gcm')!
  const gcmEnc = await gcm.process({ direction: 'encode', input: 'a secret worth protecting', fields: gcmFields })
  const gcmDec = await gcm.process({ direction: 'decode', input: gcmEnc.output, fields: gcmFields })
  let gcmTamperDetected = false
  try {
    const bytes = P.unbase64(gcmEnc.output)
    bytes[0] ^= 0xff
    await gcm.process({ direction: 'decode', input: P.base64(bytes), fields: gcmFields })
  } catch {
    gcmTamperDetected = true
  }
  check(
    'aes-gcm roundtrip + tamper detection',
    gcmDec.output === 'a secret worth protecting' && gcmTamperDetected
  )

  // -------------------------------------------------------- tokens
  const famousToken =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
    'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.' +
    'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
  const jwtResigned = await run(findMethod('jwt')!, 'encode', '{"sub":"1234567890","name":"John Doe","iat":1516239022}', {
    alg: 'HS256',
    secret: 'your-256-bit-secret',
  })
  check('jwt sign matches the jwt.io example', jwtResigned.output === famousToken, jwtResigned.output)
  const jwtDecoded = await run(findMethod('jwt')!, 'decode', famousToken, {
    alg: 'HS256',
    secret: 'your-256-bit-secret',
  })
  check('jwt verify accepts the example', (jwtDecoded.note ?? '').includes('checks out'))
  const jwtBad = await run(findMethod('jwt')!, 'decode', famousToken, {
    alg: 'HS256',
    secret: 'wrong-secret',
  })
  check('jwt verify rejects wrong secret', jwtBad.warning !== undefined)

  const jwksInspect = await run(findMethod('jwks')!, 'decode', '{"keys":[{"kty":"RSA","kid":"2011-04-29","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}]}')
  check(
    'jwks parses the RFC 7517 example key',
    jwksInspect.output.includes('2048-bit') && jwksInspect.output.includes('BEGIN PUBLIC KEY'),
    jwksInspect.output
  )

  const jwksBuilt = await run(findMethod('jwks')!, 'encode', '', { priv: rsaPair.priv, kid: 'test-kid' })
  const jwksBack = await run(findMethod('jwks')!, 'decode', jwksBuilt.output)
  check(
    'jwks build/inspect roundtrip',
    jwksBack.output.includes('test-kid') && jwksBack.output.includes('BEGIN PRIVATE KEY'),
    jwksBack.output
  )

  // -------------------------------------------------------- defuse
  // -------------------------------------------------------- mcrypt
  const mcryptVectors = await mcryptCrossVectors()
  check('mcrypt cross-language vectors (php 5.6)', mcryptVectors.pass, mcryptVectors.detail)

  const lv = (mcryptVectorsJson as Record<string, unknown>)['laravel4_payload'] as {
    key_hex: string
    payload_b64: string
  }
  const lvDecode = await run(findMethod('laravel-crypt')!, 'decode', lv.payload_b64, {
    key: lv.key_hex,
    keyenc: 'Hex',
    cipher: 'rijndael-128',
  })
  check('laravel legacy payload decrypts', lvDecode.output === 'hello from laravel four', lvDecode.output)
  let lvTamper = false
  try {
    await run(findMethod('laravel-crypt')!, 'decode', lv.payload_b64.slice(0, -4) + 'AAAA', {
      key: lv.key_hex,
      keyenc: 'Hex',
      cipher: 'rijndael-128',
    })
  } catch {
    lvTamper = true
  }
  check('laravel legacy payload detects tampering', lvTamper)

  check('defuse key save/load roundtrip', defuseKeyRoundtrip())
  check('defuse encrypt/decrypt roundtrip', defuseEncryptRoundtrip())
  check('defuse password roundtrip', defusePasswordRoundtrip())
  check('defuse tamper detection', defuseTamper())
  const crossVectors = defuseCrossVectors()
  check('defuse cross-language vectors', crossVectors.pass, crossVectors.detail)

  return cases
}

function defuseKeyRoundtrip(): boolean {
  const key = D.newKey()
  const ascii = D.saveKeyAscii(key)
  return ascii.startsWith('def00000') && P.fixedTimeEquals(D.loadKeyAscii(ascii), key)
}

function defuseEncryptRoundtrip(): boolean {
  const key = D.newKey()
  const ascii = D.saveKeyAscii(key)
  const ct = D.encrypt(P.utf8Encode('roundtrip me \ud83c\udfb2'), key)
  return (
    ct.startsWith('def50200') &&
    P.utf8Decode(D.decryptHex(ct, D.loadKeyAscii(ascii))) === 'roundtrip me \ud83c\udfb2'
  )
}

function defusePasswordRoundtrip(): boolean {
  const ct = D.encryptWithPassword(P.utf8Encode('open sesame'), P.utf8Encode('hunter2'))
  return P.utf8Decode(D.decryptPasswordHex(ct, P.utf8Encode('hunter2'))) === 'open sesame'
}

function defuseTamper(): boolean {
  const key = D.newKey()
  const ct = D.encrypt(P.utf8Encode('do not touch'), key)
  try {
    const bytes = P.unhex(ct)
    bytes[bytes.length - 1] ^= 0x01
    D.decryptHex(P.hex(bytes), key)
    return false
  } catch {
    return true
  }
}

function defuseCrossVectors(): { pass: boolean; detail?: string } {
  const notes: string[] = []
  const step = (name: string, pass: boolean, note: string) => {
    if (!pass) notes.push(`${name}: ${note}`)
  }

  try {
    if (vectors.v2_key) {
      const key = D.loadKeyAscii(vectors.v2_key.key_ascii)
      const pt = D.decryptHex(vectors.v2_key.ciphertext_hex, key)
      step('php key ciphertext decrypts', P.utf8Decode(pt) === vectors.v2_key.plaintext, 'plaintext mismatch')
    }

    if (vectors.v2_password) {
      const pt = D.decryptPasswordHex(
        vectors.v2_password.ciphertext_hex,
        P.utf8Encode(vectors.v2_password.password)
      )
      step(
        'php password ciphertext decrypts',
        P.utf8Decode(pt) === vectors.v2_password.plaintext,
        'plaintext mismatch'
      )
    }

    if (vectors.v2_kat) {
      const ct = P.hex(
        D.encryptRaw(
          P.utf8Encode(vectors.v2_kat.plaintext),
          P.unhex(vectors.v2_kat.key_hex),
          P.unhex(vectors.v2_kat.salt_hex),
          P.unhex(vectors.v2_kat.iv_hex)
        )
      )
      step(
        'fixed salt/iv KAT matches php',
        ct === vectors.v2_kat.ciphertext_hex,
        `got ${ct.substring(0, 24)}..., want ${vectors.v2_kat.ciphertext_hex.substring(0, 24)}...`
      )
    }

    if (vectors.v2_password_kat) {
      const ct = P.hex(
        D.encryptPasswordRaw(
          P.utf8Encode(vectors.v2_password_kat.plaintext),
          P.utf8Encode(vectors.v2_password_kat.password),
          P.unhex(vectors.v2_password_kat.salt_hex),
          P.unhex(vectors.v2_password_kat.iv_hex)
        )
      )
      step(
        'password fixed salt/iv KAT matches php',
        ct === vectors.v2_password_kat.ciphertext_hex,
        'ciphertext mismatch'
      )
    }

    if (vectors.key_wrap) {
      const unlocked = D.unlockProtectedKey(
        vectors.key_wrap.protected_key_ascii,
        vectors.key_wrap.password
      )
      step(
        'php password-protected key unlocks',
        D.saveKeyAscii(unlocked) === vectors.key_wrap.inner_key_ascii,
        'unlocked key mismatch'
      )
    }

    if (vectors.legacy_kat) {
      const pt = D.legacyDecrypt(vectors.legacy_kat.ciphertext_hex, P.unhex(vectors.legacy_kat.key_hex))
      step(
        'legacy v1 ciphertext decrypts',
        P.utf8Decode(pt) === vectors.legacy_kat.plaintext,
        'plaintext mismatch'
      )
    }

    return notes.length === 0
      ? { pass: true }
      : { pass: false, detail: notes.join('; ') }
  } catch (e) {
    return { pass: false, detail: `vector file problem: ${e instanceof Error ? e.message : String(e)}` }
  }
}

async function mcryptCrossVectors(): Promise<{ pass: boolean; detail?: string }> {
  const method = findMethod('mcrypt')!
  const notes: string[] = []
  let total = 0
  for (const [id, raw] of Object.entries(mcryptVectorsJson as Record<string, unknown>)) {
    if (id === 'laravel4_payload') continue
    const v = raw as {
      algorithm: string
      mode: string
      key_hex: string
      iv_hex: string
      plaintext_hex: string
      ciphertext_hex: string
      decrypted_hex: string
    }
    total++
    const fields: Record<string, string> = {
      algo: v.algorithm,
      mode: v.mode,
      key: v.key_hex,
      keyenc: 'Hex',
      iv: v.iv_hex ?? '',
      ivenc: 'Hex',
      out: 'Hex',
    }
    try {
      const plaintext = P.utf8Decode(P.unhex(v.plaintext_hex))
      const enc = await method.process({ direction: 'encode', input: plaintext, fields })
      if (enc.output.toLowerCase() !== v.ciphertext_hex.toLowerCase()) {
        notes.push(`${id}: encrypt mismatch`)
        continue
      }
      const dec = await method.process({ direction: 'decode', input: v.ciphertext_hex, fields })
      const stripped = P.utf8Decode(P.unhex(v.decrypted_hex || v.plaintext_hex))
      let end = stripped.length
      while (end > 0 && stripped.charCodeAt(end - 1) === 0) end--
      const want = stripped.slice(0, end)
      if (dec.output !== want) notes.push(`${id}: decrypt mismatch`)
    } catch (e) {
      notes.push(`${id}: threw ${e instanceof Error ? e.message : String(e)}`)
    }
  }
  return notes.length === 0
    ? { pass: true }
    : { pass: false, detail: `of ${total} cases: ` + notes.join('; ') }
}

/** Format the failure notes for display. */
export function selfTestDetail(cases: TestCase[]): string {
  const failed = cases.filter((c) => !c.pass)
  return failed.length === 0
    ? `all ${cases.length} checks pass`
    : failed.map((c) => `${c.name}${c.detail ? `: ${c.detail}` : ''}`).join('; ')
}
