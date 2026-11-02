/** Generalized Rijndael: the AES ancestor with variable BLOCK sizes.
 * MCRYPT_RIJNDAEL_128 is AES, but MCRYPT_RIJNDAEL_192 and _256 use 24- and
 * 32-byte blocks, which standard AES libraries refuse - the classic legacy
 * PHP gotcha. Nr = max(Nb, Nk) + 6, shift offsets {0,1,2,3} for Nb 4/6 and
 * {0,1,3,4} for Nb 8, per the original Rijndael specification.
 *
 * The S-box is computed algebraically (GF(2^8) inverse + affine transform)
 * instead of being transcribed, so a typo is impossible; the module pins it
 * against known values at load. Pinned end to end by the real-mcrypt
 * cross-language vectors in tests/. */

const SBOX = buildSbox()
const INV_SBOX = buildInverseSbox(SBOX)

function buildSbox(): Uint8Array {
  // exp/log tables over GF(2^8) with generator 3.
  const exp = new Uint8Array(255)
  const log = new Uint8Array(256)
  let x = 1
  for (let i = 0; i < 255; i++) {
    exp[i] = x
    log[x] = i
    // x *= 3 in GF(2^8): double, then xor the double back in.
    const double = ((x << 1) ^ (x & 0x80 ? 0x11b : 0)) & 0xff
    x = double ^ x
  }
  const box = new Uint8Array(256)
  for (let b = 0; b < 256; b++) {
    const inv = b === 0 ? 0 : exp[(255 - log[b]) % 255]
    const rot = (v: number, n: number) => ((v << n) | (v >>> (8 - n))) & 0xff
    box[b] = (inv ^ rot(inv, 1) ^ rot(inv, 2) ^ rot(inv, 3) ^ rot(inv, 4) ^ 0x63) & 0xff
  }
  return box
}

function buildInverseSbox(box: Uint8Array): Uint8Array {
  const inv = new Uint8Array(256)
  for (let i = 0; i < 256; i++) inv[box[i]] = i
  return inv
}

// Pin the computed S-box: these three values open the published AES table.
if (SBOX[0x00] !== 0x63 || SBOX[0x01] !== 0x7c || SBOX[0x53] !== 0xed)
  throw new Error('rijndael s-box self-check failed')

const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d]

export type BlockWords = 4 | 6 | 8

export interface RijndaelCipher {
  blockSize: number
  encryptBlock(input: Uint8Array, inOff: number, out: Uint8Array, outOff: number): void
  decryptBlock(input: Uint8Array, inOff: number, out: Uint8Array, outOff: number): void
}

export function rijndael(nb: BlockWords, key: Uint8Array): RijndaelCipher {
  const nk = (key.length / 4) as BlockWords
  const nr = Math.max(nb, nk) + 6
  const roundsWords = nb * (nr + 1)

  // Key schedule: state as columns of 4 bytes, each column one 32-bit word
  // stored little-endian (byte0 = LSB) the way the AES spec writes w[i].
  const w = new Uint32Array(roundsWords)
  for (let i = 0; i < nk; i++) {
    w[i] =
      (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3]
  }
  for (let i = nk; i < roundsWords; i++) {
    let temp = w[i - 1]
    if (i % nk === 0) {
      temp = subWord(rotWord(temp)) ^ (RCON[i / nk - 1] << 24)
    } else if (nk > 6 && i % nk === 4) {
      temp = subWord(temp)
    }
    w[i] = (w[i - nk] ^ temp) >>> 0
  }

  const shiftOffsets = nb === 8 ? [0, 1, 3, 4] : [0, 1, 2, 3]

  const mixColumn = (state: Uint8Array, col: number) => {
    const a0 = state[col]
    const a1 = state[col + 1]
    const a2 = state[col + 2]
    const a3 = state[col + 3]
    state[col] = xt(a0) ^ (xt(a1) ^ a1) ^ a2 ^ a3
    state[col + 1] = a0 ^ xt(a1) ^ (xt(a2) ^ a2) ^ a3
    state[col + 2] = a0 ^ a1 ^ xt(a2) ^ (xt(a3) ^ a3)
    state[col + 3] = (xt(a0) ^ a0) ^ a1 ^ a2 ^ xt(a3)
  }

  const invMixColumn = (state: Uint8Array, col: number) => {
    const a0 = state[col]
    const a1 = state[col + 1]
    const a2 = state[col + 2]
    const a3 = state[col + 3]
    state[col] = xe(a0) ^ xm(a1) ^ xd(a2) ^ x9(a3)
    state[col + 1] = x9(a0) ^ xe(a1) ^ xm(a2) ^ xd(a3)
    state[col + 2] = xd(a0) ^ x9(a1) ^ xe(a2) ^ xm(a3)
    state[col + 3] = xm(a0) ^ xd(a1) ^ x9(a2) ^ xe(a3)
  }

  function crypt(input: Uint8Array, inOff: number, out: Uint8Array, outOff: number, decrypt: boolean) {
    // state[r][c] stored at state[c*4 + r], column-major like FIPS-197.
    const s = new Uint8Array(nb * 4)
    for (let c = 0; c < nb; c++)
      for (let r = 0; r < 4; r++) s[c * 4 + r] = input[inOff + 4 * c + r]

    if (decrypt) {
      // FIPS-197 InvCipher, generalized: ARK(nr); for rounds nr-1..1
      // { InvShift, InvSub, ARK, InvMix }; then undo round zero.
      addRoundKey(s, nr)
      for (let round = nr - 1; round >= 1; round--) {
        invShiftRows(s)
        subBytes(s, INV_SBOX)
        addRoundKey(s, round)
        for (let c = 0; c < nb; c++) invMixColumn(s, c * 4)
      }
      invShiftRows(s)
      subBytes(s, INV_SBOX)
      addRoundKey(s, 0)
    } else {
      addRoundKey(s, 0)
      for (let round = 1; round < nr; round++) {
        subBytes(s, SBOX)
        shiftRows(s)
        for (let c = 0; c < nb; c++) mixColumn(s, c * 4)
        addRoundKey(s, round)
      }
      subBytes(s, SBOX)
      shiftRows(s)
      addRoundKey(s, nr)
    }

    for (let c = 0; c < nb; c++)
      for (let r = 0; r < 4; r++) out[outOff + 4 * c + r] = s[c * 4 + r]
  }

  function addRoundKey(s: Uint8Array, round: number) {
    for (let c = 0; c < nb; c++) {
      const word = w[round * nb + c]
      // w's byte0 is the MSB of the word as built; state row 0 is the first
      // byte of the column, so XOR big-endian byte order.
      s[c * 4] ^= (word >>> 24) & 0xff
      s[c * 4 + 1] ^= (word >>> 16) & 0xff
      s[c * 4 + 2] ^= (word >>> 8) & 0xff
      s[c * 4 + 3] ^= word & 0xff
    }
  }

  function shiftRows(s: Uint8Array) {
    shift(s, false)
  }

  function invShiftRows(s: Uint8Array) {
    shift(s, true)
  }

  function shift(s: Uint8Array, inverse: boolean) {
    for (let r = 1; r < 4; r++) {
      const off = shiftOffsets[r]
      const row = new Uint8Array(nb)
      for (let c = 0; c < nb; c++) {
        // Forward: row shifts left by off (new[c] = old[c+off]).
        // Inverse: row shifts right by off (new[c+off] = old[c]).
        const src = inverse ? c : (c + off) % nb
        const dst = inverse ? (c + off) % nb : c
        row[dst] = s[src * 4 + r]
      }
      for (let c = 0; c < nb; c++) s[c * 4 + r] = row[c]
    }
  }

  function subBytes(s: Uint8Array, box: Uint8Array) {
    for (let i = 0; i < s.length; i++) s[i] = box[s[i]]
  }

  return {
    blockSize: nb * 4,
    encryptBlock(input, inOff, out, outOff) {
      crypt(input, inOff, out, outOff, false)
    },
    decryptBlock(input, inOff, out, outOff) {
      crypt(input, inOff, out, outOff, true)
    },
  }
}

function subWord(word: number): number {
  return (
    ((SBOX[(word >>> 24) & 0xff] << 24) |
      (SBOX[(word >>> 16) & 0xff] << 16) |
      (SBOX[(word >>> 8) & 0xff] << 8) |
      SBOX[word & 0xff]) >>>
    0
  )
}

function rotWord(word: number): number {
  return ((word << 8) | (word >>> 24)) >>> 0
}

// GF(2^8) multiply helpers.
function xtime(b: number): number {
  return ((b << 1) ^ (b & 0x80 ? 0x1b : 0)) & 0xff
}
function xt(b: number): number {
  return xtime(b)
}
function gmul(b: number, m: number): number {
  let acc = 0
  let x = b
  for (let i = 0; i < 8; i++) {
    if (m & (1 << i)) acc ^= x
    x = xtime(x)
  }
  return acc & 0xff
}
function x9(b: number): number {
  return gmul(b, 0x09)
}
function xd(b: number): number {
  return gmul(b, 0x0d)
}
function xe(b: number): number {
  return gmul(b, 0x0e)
}
function xm(b: number): number {
  return gmul(b, 0x0b)
}
