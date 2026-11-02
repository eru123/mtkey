/** Blowfish (Bruce Schneier, 1993), the block cipher behind MCRYPT_BLOWFISH
 * and a decade of legacy PHP payloads. 16-round Feistel network on 64-bit
 * blocks, variable key length 4..56 bytes. The initial P-array and S-boxes
 * are the hex digits of pi's fraction (blowfish-tables.ts); the key
 * schedule re-chains them exactly as the reference implementation does.
 * Pinned by the real-mcrypt cross-language vectors in tests/. */
import { P_INIT, S_INIT } from './blowfish-tables'

const MASK = 0xffffffff

interface Tables {
  p: Uint32Array
  s: Uint32Array[]
}

/** The i-th big-endian 32-bit word of the (cyclically repeated) key. */
function keyWord(key: Uint8Array, i: number): number {
  let word = 0
  for (let b = 0; b < 4; b++) word = ((word << 8) | key[(i * 4 + b) % key.length]) >>> 0
  return word
}

function f(t: Tables, x: number): number {
  const a = (x >>> 24) & 0xff
  const b = (x >>> 16) & 0xff
  const c = (x >>> 8) & 0xff
  const d = x & 0xff
  return (((((t.s[0][a] + t.s[1][b]) & MASK) ^ t.s[2][c]) + t.s[3][d]) & MASK) >>> 0
}

function block(t: Tables, l: number, r: number, decrypt: boolean): [number, number] {
  let x = l
  let y = r
  if (decrypt) {
    for (let i = 17; i >= 3; i -= 2) {
      x ^= t.p[i]
      y ^= f(t, x)
      y ^= t.p[i - 1]
      x ^= f(t, y)
    }
    x ^= t.p[1]
    y ^= t.p[0]
  } else {
    for (let i = 0; i < 16; i += 2) {
      x ^= t.p[i]
      y ^= f(t, x)
      y ^= t.p[i + 1]
      x ^= f(t, y)
    }
    x ^= t.p[16]
    y ^= t.p[17]
  }
  return [y, x]
}

/** Build the key-dependent tables: XOR the key into P cyclically, then
 * chain-encrypt the all-zero block through P and the S-boxes in order. */
function makeTables(key: Uint8Array): Tables {
  const t: Tables = {
    p: Uint32Array.from(P_INIT),
    s: [
      Uint32Array.from(S_INIT[0]),
      Uint32Array.from(S_INIT[1]),
      Uint32Array.from(S_INIT[2]),
      Uint32Array.from(S_INIT[3]),
    ],
  }
  for (let i = 0; i < 18; i++) t.p[i] = (t.p[i] ^ keyWord(key, i)) >>> 0

  let l = 0
  let r = 0
  for (let i = 0; i < 18; i += 2) {
    ;[l, r] = block(t, l, r, false)
    t.p[i] = l
    t.p[i + 1] = r
  }
  for (let box = 0; box < 4; box++) {
    for (let i = 0; i < 256; i += 2) {
      ;[l, r] = block(t, l, r, false)
      t.s[box][i] = l
      t.s[box][i + 1] = r
    }
  }
  return t
}

/** Encrypt or decrypt an 8-byte aligned buffer in place. */
export function blowfishCrypt(key: Uint8Array, data: Uint8Array, decrypt: boolean): Uint8Array {
  const t = makeTables(key)
  for (let off = 0; off < data.length; off += 8) {
    const l =
      ((data[off] << 24) | (data[off + 1] << 16) | (data[off + 2] << 8) | data[off + 3]) >>> 0
    const r =
      ((data[off + 4] << 24) | (data[off + 5] << 16) | (data[off + 6] << 8) | data[off + 7]) >>> 0
    const [outL, outR] = block(t, l, r, decrypt)
    data[off] = (outL >>> 24) & 0xff
    data[off + 1] = (outL >>> 16) & 0xff
    data[off + 2] = (outL >>> 8) & 0xff
    data[off + 3] = outL & 0xff
    data[off + 4] = (outR >>> 24) & 0xff
    data[off + 5] = (outR >>> 16) & 0xff
    data[off + 6] = (outR >>> 8) & 0xff
    data[off + 7] = outR & 0xff
  }
  return data
}
