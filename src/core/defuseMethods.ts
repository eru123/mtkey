/** The defuse/php-encryption suite, ported byte-for-byte so ciphertexts
 * interoperate with PHP apps using the library. Ported from the C#
 * Methods_Defuse with the explainer copy intact. */
import {
  CipherError,
  defineMethod,
  field,
  validation,
  emptyValidation,
  type CipherMethod,
  type FieldValidation,
} from './types'
import { unhex, utf8Encode, utf8Decode } from './primitives'
import * as defuse from './defuse'

export const defuseKeyMethod: CipherMethod = defineMethod({
  id: 'defuse-encrypt',
  name: 'Defuse Authenticated (key)',
  category: 'PHP Interop',
  blurb: 'defuse/php-encryption v2 with a stored key. Ciphertexts start with def502.',
  learn:
    'This is a byte-for-byte port of Defuse\\Crypto\\Crypto::encrypt, the authenticated ' +
    'encryption used by many PHP applications. Inside: a random 32-byte salt and 16-byte ' +
    'IV per message, HKDF splitting the key into an encryption key and an authentication ' +
    'key, AES-256-CTR for secrecy and HMAC-SHA256 over everything for tamper detection. ' +
    'Ciphertexts are plain lowercase hex, which is why they all start with def502 (the ' +
    'hex of the version bytes DE F5 02 00). Strings encrypted by the PHP library load ' +
    'here, and strings encrypted here load in PHP.',
  wikiUrl: 'https://github.com/defuse/php-encryption',
  aliases: ['defuse', 'def502'],
  fields: [
    {
      name: 'key',
      label: 'Defuse key',
      secret: true,
      placeholder: 'def00000...',
      hint: 'The def00000... string from Key::saveToAsciiSafeString. Dice mints one.',
      generator: 'defuseKey',
    },
  ],
  process: async (r) => {
    const keyText = field(r, 'key').trim()
    if (keyText.length === 0)
      throw new CipherError('Paste a defuse key (def00000...) or roll one with the dice.')
    const key = defuse.loadKeyAscii(keyText)

    if (r.direction === 'encode')
      return {
        output: defuse.encrypt(utf8Encode(r.input), key),
        note: 'AES-256-CTR + HMAC-SHA256, fresh salt and IV every time.',
      }

    return { output: utf8Decode(defuse.decryptHex(r.input, key)) }
  },
  validateFields: async (values): Promise<FieldValidation> => {
    const result = emptyValidation()
    const keyText = (values['key'] ?? '').trim()
    if (keyText.length > 0) {
      const { ok, error } = defuse.tryValidateKeyAscii(keyText)
      result.fields['key'] = ok
        ? validation.good('Checksum OK, 32-byte key')
        : validation.bad(error)
    }
    return result
  },
})

export const defusePasswordMethod: CipherMethod = defineMethod({
  id: 'defuse-password',
  name: 'Defuse With Password',
  category: 'PHP Interop',
  blurb: 'Same format, but the key is stretched from a human password.',
  learn:
    'Crypto::encryptWithPassword runs the password through SHA-256, then PBKDF2-HMAC-SHA256 ' +
    '100,000 times with the message salt, then HKDF, before the same AES-CTR + HMAC core ' +
    'runs. The point of the slow KDF is cost: every wrong password guess an attacker makes ' +
    'pays the 100k iterations too. Compare that with using a password directly as an AES ' +
    'key, where each guess is one fast AES operation.',
  wikiUrl: 'https://github.com/defuse/php-encryption',
  aliases: ['defuse'],
  fields: [
    {
      name: 'password',
      label: 'Password',
      secret: true,
      placeholder: 'correct horse battery staple',
      hint: 'Slow-derived (PBKDF2, 100k rounds) into the encryption and auth keys.',
      generator: 'password',
    },
  ],
  process: async (r) => {
    const password = field(r, 'password')
    if (password.length === 0)
      throw new CipherError('A password is needed for this method.')

    if (r.direction === 'encode')
      return {
        output: defuse.encryptWithPassword(utf8Encode(r.input), utf8Encode(password)),
        note: 'PBKDF2 100,000 rounds + HKDF + AES-256-CTR + HMAC-SHA256.',
      }

    return { output: utf8Decode(defuse.decryptPasswordHex(r.input, utf8Encode(password))) }
  },
})

export const defuseKeyToolMethod: CipherMethod = defineMethod({
  id: 'defuse-key',
  name: 'Defuse Key Tool',
  category: 'PHP Interop',
  blurb: 'Generate, protect and unlock def00000 keys, including def10000 password-wrapped ones.',
  learn:
    'The PHP library stores keys as hex with a built-in SHA-256 checksum (def00000...). ' +
    'KeyProtectedByPassword wraps a real key inside password encryption, giving a ' +
    'def10000... string you can keep on a web server: the app can unlock it at runtime ' +
    'with the password, but a backup leak alone does not reveal the key. Encode here ' +
    'mints or wraps keys; Decode unwraps a def10000 string back into its def00000 key.',
  wikiUrl: 'https://github.com/defuse/php-encryption',
  aliases: ['defuse', 'keygen', 'def10000'],
  encodeLabel: 'Generate / wrap',
  decodeLabel: 'Unlock',
  fields: [
    {
      name: 'mode',
      label: 'Action',
      kind: 'dropdown',
      options: ['New raw key (def00000)', 'Wrap key with password (def10000)'],
      default: 'New raw key (def00000)',
      hint: 'Wrapping needs the password below; a fresh random key is minted when its field is empty.',
    },
    {
      name: 'key',
      label: 'Raw key',
      kind: 'multiline',
      secret: true,
      placeholder: 'def00000... (leave empty to mint a new one)',
      hint: 'For wrapping: the key to protect. Empty means generate fresh.',
      generator: 'defuseKey',
    },
    {
      name: 'password',
      label: 'Password',
      secret: true,
      placeholder: 'only needed for wrapping and unlocking',
      generator: 'password',
    },
  ],
  process: async (r) => {
    if (r.direction === 'encode') {
      const mode = field(r, 'mode')
      if (mode.startsWith('Wrap')) {
        const password = field(r, 'password')
        if (password.length === 0) throw new CipherError('Wrapping needs a password.')
        const keyText = field(r, 'key').trim()
        const key = keyText.length > 0 ? defuse.loadKeyAscii(keyText) : defuse.newKey()
        return {
          output: defuse.wrapProtected(key, password),
          note:
            keyText.length > 0
              ? 'Wrapped your key. Store the def10000 string, keep the password elsewhere.'
              : 'Minted a fresh key and wrapped it. Save the def10000 string AND the password.',
        }
      }

      const keyText = field(r, 'key').trim()
      const key = keyText.length > 0 ? defuse.loadKeyAscii(keyText) : defuse.newKey()
      return {
        output: defuse.saveKeyAscii(key),
        note: 'Share only with systems that need to encrypt or decrypt.',
      }
    }

    const wrapped = r.input.trim()
    if (wrapped.length === 0)
      throw new CipherError('Paste a def10000... password-protected key to unlock.')
    const password = field(r, 'password')
    if (password.length === 0)
      throw new CipherError('Unlocking needs the password it was wrapped with.')
    const raw = defuse.unlockProtectedKey(wrapped, password)
    return {
      output: defuse.saveKeyAscii(raw),
      note: 'Unlocked. This def00000 key is now bare, handle it accordingly.',
    }
  },
})

export const defuseLegacyMethod: CipherMethod = defineMethod({
  id: 'defuse-legacy',
  name: 'Defuse v1 (legacy decrypt)',
  category: 'PHP Interop',
  blurb: 'Reads ciphertext from version 1.x of the library. Decrypt only.',
  learn:
    'Version 1 of defuse/php-encryption used AES-128-CBC with HMAC-SHA256 and put the ' +
    'MAC at the FRONT of the string, before the IV. Version 2 switched to CTR mode, ' +
    'added per-message salts and moved the MAC to the end. This method exists so old ' +
    'data can still be read; it will never produce new v1 ciphertext.',
  wikiUrl: 'https://github.com/defuse/php-encryption',
  twoWay: false,
  encodeLabel: 'n/a',
  decodeLabel: 'Decrypt',
  fields: [
    {
      name: 'key',
      label: 'Raw v1 key (hex)',
      secret: true,
      placeholder: '32 hex digits = 16 bytes',
      hint: 'v1 used 128-bit keys, entered here as 32 hex characters.',
      generator: 'hexBytes',
      generatorSize: 16,
    },
  ],
  process: async (r) => {
    const key = unhex(field(r, 'key').trim())
    return { output: utf8Decode(defuse.legacyDecrypt(r.input, key)) }
  },
})

export const defuseMethods: readonly CipherMethod[] = [
  defuseKeyMethod,
  defusePasswordMethod,
  defuseKeyToolMethod,
  defuseLegacyMethod,
]
