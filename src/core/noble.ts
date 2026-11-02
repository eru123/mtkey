/** Central re-export of every @noble/hashes import the core uses, so an
 * upstream package reshuffle only ever touches this one file. v2 of the
 * package exports subpaths with an explicit .js suffix. */
import { md5, sha1 } from '@noble/hashes/legacy.js'
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js'
import { sha3_256 } from '@noble/hashes/sha3.js'
import { hmac } from '@noble/hashes/hmac.js'
import { pbkdf2 } from '@noble/hashes/pbkdf2.js'

export const md5Hash = md5
export const sha1Hash = sha1
export const sha256Hash = sha256
export const sha384Hash = sha384
export const sha512Hash = sha512
export const sha3_256Hash = sha3_256
export { hmac, pbkdf2 }
