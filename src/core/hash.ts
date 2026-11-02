/** The Hash methods: MD5, SHA-1/256/384/512, SHA-3-256, the HMAC family,
 * CRC-32 and PBKDF2. Ported from the C# Methods_Hash with the explainer
 * copy intact. Digests come from @noble/hashes; SHA-3 no longer depends on
 * the platform, so it ships on every OS now. */
import {
  CipherError,
  defineMethod,
  field,
  type CipherMethod,
  type CipherResult,
  type FieldSpec,
} from './types'
import type { CHash } from '@noble/hashes/utils.js'
import { base64, crc32, hex, pbkdf2Sha256, utf8Encode } from './primitives'
import { hmac } from '@noble/hashes/hmac.js'
import {
  md5Hash,
  sha1Hash,
  sha256Hash,
  sha384Hash,
  sha512Hash,
  sha3_256Hash,
} from './noble'

const OUTPUT_FIELD: FieldSpec = {
  name: 'out',
  label: 'Output',
  kind: 'dropdown',
  options: ['Hex', 'Base64'],
  default: 'Hex',
}

function render(digest: Uint8Array, encoding: string): string {
  return encoding === 'Base64' ? base64(digest) : hex(digest)
}

interface HashSpec {
  id: string
  name: string
  blurb: string
  learn: string
  wiki: string
  hash: (data: Uint8Array) => Uint8Array
  aliases?: string[]
}

const HASH_SPECS: readonly HashSpec[] = [
  {
    id: 'md5',
    name: 'MD5',
    blurb: '128-bit hash from 1991, broken for signatures since 2004.',
    learn:
      'MD5 was everywhere: file checksums, password storage, certificate signatures. ' +
      'Researchers then found ways to craft two different inputs with the same MD5, and ' +
      'real certificates were forged with the trick in 2008. It still works fine as a ' +
      'fingerprint for accidental corruption, but never trust it against an attacker.',
    wiki: 'https://en.wikipedia.org/wiki/MD5',
    hash: md5Hash,
    aliases: ['digest'],
  },
  {
    id: 'sha1',
    name: 'SHA-1',
    blurb: '160-bit hash, officially retired in 2017.',
    learn:
      'SHA-1 was the standard hash for two decades. Google and CWI Amsterdam pulled off ' +
      'the first practical collision in 2017 (two different PDFs, same SHA-1) at a cost ' +
      'of about 110 GPU-years. Browsers dropped it the same year. Interesting fact: ' +
      'Git still uses SHA-1 internally, with extra checks layered on top.',
    wiki: 'https://en.wikipedia.org/wiki/SHA-1',
    hash: sha1Hash,
    aliases: ['digest'],
  },
  {
    id: 'sha256',
    name: 'SHA-256',
    blurb: 'The workhorse of modern hashing.',
    learn:
      'SHA-256 belongs to the SHA-2 family designed by the NSA and published in 2001. ' +
      'It guards TLS certificates, Bitcoin proof-of-work, package signatures and JWT ' +
      'signing (the RS256 and HS256 you see in tokens are SHA-256 inside). No practical ' +
      'attack is known against it.',
    wiki: 'https://en.wikipedia.org/wiki/SHA-2',
    hash: sha256Hash,
    aliases: ['sha2', 'sha-256', 'digest'],
  },
  {
    id: 'sha384',
    name: 'SHA-384',
    blurb: 'SHA-2 with a 384-bit digest.',
    learn:
      'SHA-384 is SHA-512 with two thirds of the output and different starting values. ' +
      "You meet it in TLS cipher suites and in JWT's RS384/HS384 algorithms where a " +
      '192-bit security level is wanted.',
    wiki: 'https://en.wikipedia.org/wiki/SHA-2',
    hash: sha384Hash,
    aliases: ['sha2', 'digest'],
  },
  {
    id: 'sha512',
    name: 'SHA-512',
    blurb: 'SHA-2 with the full 512-bit digest.',
    learn:
      'SHA-512 processes data in 64-bit words, which makes it fast on 64-bit CPUs, ' +
      'sometimes faster than SHA-256. Password hashes based on raw SHA-512 are a bad ' +
      'idea though, it is too quick; that is what PBKDF2 and friends are for.',
    wiki: 'https://en.wikipedia.org/wiki/SHA-2',
    hash: sha512Hash,
    aliases: ['sha2', 'digest'],
  },
  {
    id: 'sha3-256',
    name: 'SHA-3 (256)',
    blurb: 'The newest NIST hash standard, a totally different design.',
    learn:
      'SHA-3 came from the Keccak sponge construction, chosen by NIST in 2012 after ' +
      'cryptographers worried SHA-2 might fall the way SHA-1 did. It squeezes output ' +
      'from a soaked sponge state rather than compressing blocks, so it is built on ' +
      'entirely different mathematics than the SHA-1/SHA-2 family.',
    wiki: 'https://en.wikipedia.org/wiki/SHA-3',
    hash: sha3_256Hash,
    aliases: ['keccak', 'digest'],
  },
]

function hashMethod(spec: HashSpec): CipherMethod {
  return defineMethod({
    id: spec.id,
    name: spec.name,
    category: 'Hash',
    blurb: spec.blurb,
    learn: spec.learn,
    wikiUrl: spec.wiki,
    twoWay: false,
    encodeLabel: 'Hash',
    decodeLabel: 'n/a',
    aliases: spec.aliases ?? [],
    fields: [OUTPUT_FIELD],
    process: async (r) => ({
      output: render(spec.hash(utf8Encode(r.input)), field(r, 'out')),
    }),
  })
}

interface HmacSpec {
  id: string
  name: string
  blurb: string
  learn: string
  hash: (data: Uint8Array) => Uint8Array
}

const HMAC_SPECS: readonly HmacSpec[] = [
  {
    id: 'hmac-md5',
    name: 'HMAC-MD5',
    blurb: 'MAC built on MD5. Educational only.',
    learn:
      'HMAC wraps a hash with a secret key so only key holders can reproduce the tag. ' +
      'Even though plain MD5 is collision-broken, HMAC-MD5 has no practical break, but ' +
      'nobody should pick it in 2026 when HMAC-SHA256 costs the same.',
    hash: md5Hash,
  },
  {
    id: 'hmac-sha1',
    name: 'HMAC-SHA1',
    blurb: 'Keyed hash on SHA-1.',
    learn:
      'HMAC-SHA1 still appears in older APIs and AWS Signature V3-era tooling. ' +
      'It works, but every new system should reach for a SHA-2 based MAC.',
    hash: sha1Hash,
  },
  {
    id: 'hmac-sha256',
    name: 'HMAC-SHA256',
    blurb: 'Keyed hash on SHA-256. The default MAC.',
    learn:
      'HMAC-SHA256 is the integrity half of TLS records, the JWT HS256 algorithm, ' +
      'AWS Signature V4, TOTP authenticator codes and the defuse library\u2019s ' +
      'authentication layer. Knowing the hash reveals nothing; the key is what ' +
      'makes the tag unforgeable.',
    hash: sha256Hash,
  },
  {
    id: 'hmac-sha512',
    name: 'HMAC-SHA512',
    blurb: 'Keyed hash on SHA-512.',
    learn:
      'The long version of HMAC-SHA256, used where a 256-bit tag is wanted, for ' +
      'example in JWT HS512 and some blockchain signing schemes.',
    hash: sha512Hash,
  },
]

function hmacMethod(spec: HmacSpec): CipherMethod {
  return defineMethod({
    id: spec.id,
    name: spec.name,
    category: 'Hash',
    blurb: spec.blurb,
    learn: spec.learn,
    wikiUrl: 'https://en.wikipedia.org/wiki/HMAC',
    twoWay: false,
    encodeLabel: 'Hash',
    decodeLabel: 'n/a',
    fields: [
      {
        name: 'key',
        label: 'Secret key',
        secret: true,
        placeholder: 'correct horse battery staple',
        hint: 'Only someone with this exact key can produce the same digest.',
        generator: 'password',
        generatorSize: 24,
      },
      OUTPUT_FIELD,
    ],
    process: async (r) => {
      const key = utf8Encode(field(r, 'key'))
      if (key.length === 0) throw new CipherError('HMAC needs a secret key.')
      const digest = hmac(spec.hash as CHash, key, utf8Encode(r.input))
      return { output: render(digest, field(r, 'out')) }
    },
  })
}

export const crc32Method: CipherMethod = defineMethod({
  id: 'crc32',
  name: 'CRC-32',
  category: 'Hash',
  blurb: 'A checksum for spotting corruption, not a cryptographic hash.',
  learn:
    'CRC-32 produces a 32-bit check value that changes when data changes. It catches ' +
    'accidental corruption (network noise, disk errors) but is trivial to fake on ' +
    'purpose, so it protects against accidents, never against attackers. ZIP files, ' +
    'Ethernet frames and PNG images carry one.',
  wikiUrl: 'https://en.wikipedia.org/wiki/CRC-32',
  twoWay: false,
  encodeLabel: 'Hash',
  decodeLabel: 'n/a',
  fields: [OUTPUT_FIELD],
  process: async (r): Promise<CipherResult> => {
    const crc = crc32(utf8Encode(r.input))
    const hexOut = crc.toString(16).padStart(8, '0')
    return {
      output:
        field(r, 'out') === 'Base64'
          ? base64(Uint8Array.from([(crc >>> 24) & 0xff, (crc >>> 16) & 0xff, (crc >>> 8) & 0xff, crc & 0xff]))
          : hexOut,
      note: `0x${hexOut.toUpperCase()}`,
    }
  },
})

export const pbkdf2Method: CipherMethod = defineMethod({
  id: 'pbkdf2',
  name: 'PBKDF2',
  category: 'Hash',
  blurb: 'Stretches a password into a key by hashing it thousands of times.',
  learn:
    'Passwords make weak keys because humans pick guessable ones. PBKDF2 repeats ' +
    'HMAC-SHA256 tens or hundreds of thousands of times so that each password guess ' +
    'costs an attacker real computing time. The salt makes precomputed password tables ' +
    'useless. WPA2 WiFi, KeePass and many password vaults use PBKDF2; the defuse ' +
    'password mode below uses 100,000 rounds, a number that keeps rising as computers ' +
    'get faster.',
  wikiUrl: 'https://en.wikipedia.org/wiki/PBKDF2',
  twoWay: false,
  encodeLabel: 'Hash',
  decodeLabel: 'n/a',
  aliases: ['kdf'],
  fields: [
    {
      name: 'password',
      label: 'Password',
      secret: true,
      placeholder: 'hunter2',
      generator: 'password',
    },
    {
      name: 'salt',
      label: 'Salt',
      placeholder: 'sea salt, kosher salt, any random text',
      hint: 'Random per user. Stored next to the hash, never secret itself.',
      generator: 'textSalt',
      generatorSize: 16,
    },
    {
      name: 'iterations',
      label: 'Iterations',
      kind: 'number',
      default: '100000',
      min: 1,
      max: 10_000_000,
      hint: "Higher is safer and slower. 100k is the defuse library's choice.",
    },
    OUTPUT_FIELD,
  ],
  process: async (r): Promise<CipherResult> => {
    const iters = Number.parseInt(field(r, 'iterations').trim(), 10)
    if (Number.isNaN(iters) || iters < 1 || iters > 10_000_000)
      throw new CipherError('Iterations must be between 1 and 10,000,000.')
    const salt = utf8Encode(field(r, 'salt'))
    if (salt.length === 0)
      throw new CipherError('PBKDF2 needs a salt. The dice button will invent one.')
    const key = pbkdf2Sha256(utf8Encode(field(r, 'password')), salt, iters, 32)
    return {
      output: render(key, field(r, 'out')),
      note: `PBKDF2-HMAC-SHA256, ${iters.toLocaleString('en-US')} iterations, 32-byte key`,
    }
  },
})

export const hashMethods: readonly CipherMethod[] = [
  ...HASH_SPECS.map(hashMethod),
  ...HMAC_SPECS.map(hmacMethod),
  crc32Method,
  pbkdf2Method,
]
