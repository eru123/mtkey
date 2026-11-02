#!/usr/bin/env node
/**
 * Generates the MTKey placeholder app icon as a 1024x1024 PNG.
 *
 * No dependencies: the PNG is assembled by hand (IHDR/IDAT/IEND chunks) using
 * node:zlib for deflate. The motif is a flat, full-bleed, two-tone diagonal in
 * deep indigo with a centered square frame. A later design pass can replace
 * scripts/icon-1024.png and re-run `pnpm tauri icon scripts/icon-1024.png`.
 *
 * Usage: node scripts/make-icon.mjs [output.png]
 */
import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { deflateSync } from 'node:zlib'

const SIZE = 1024
const OUT =
  process.argv[2] ?? fileURLToPath(new URL('./icon-1024.png', import.meta.url))

// Deep indigo palette (matches the --primary family the UI will refine).
const DEEP = [0x31, 0x2e, 0x81] // #312E81
const RAISED = [0x43, 0x38, 0xca] // #4338CA
const LIGHT = [0xee, 0xf2, 0xff] // #EEF2FF

const FRAME_OUTER = 320 // centered square frame, outer half-width
const FRAME_INNER = 128 // centered square frame, inner half-width

function pixel(x, y) {
  const cx = Math.abs(x - SIZE / 2)
  const cy = Math.abs(y - SIZE / 2)
  const insideFrame =
    cx <= FRAME_OUTER &&
    cy <= FRAME_OUTER &&
    (cx >= FRAME_INNER || cy >= FRAME_INNER)
  if (insideFrame) return LIGHT
  return x > y ? RAISED : DEEP
}

// --- minimal PNG encoder -----------------------------------------------------

const crcTable = new Uint32Array(256).map((_, n) => {
  let c = n
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
  return c >>> 0
})

function crc32(bytes) {
  let crc = 0xffffffff
  for (const b of bytes) crc = crcTable[(crc ^ b) & 0xff] ^ (crc >>> 8)
  return (crc ^ 0xffffffff) >>> 0
}

function chunk(type, data) {
  const out = Buffer.alloc(8 + data.length + 4)
  out.writeUInt32BE(data.length, 0)
  out.write(type, 4, 'ascii')
  data.copy(out, 8)
  out.writeUInt32BE(
    crc32(Buffer.concat([Buffer.from(type, 'ascii'), data])),
    8 + data.length,
  )
  return out
}

const ihdr = Buffer.alloc(13)
ihdr.writeUInt32BE(SIZE, 0)
ihdr.writeUInt32BE(SIZE, 4)
ihdr[8] = 8 // bit depth
ihdr[9] = 2 // color type: truecolor RGB
// ihdr[10..12] = compression 0, filter 0, interlace 0

const raw = Buffer.alloc(SIZE * (SIZE * 3 + 1))
let o = 0
for (let y = 0; y < SIZE; y++) {
  raw[o++] = 0 // filter type: none
  for (let x = 0; x < SIZE; x++) {
    const [r, g, b] = pixel(x, y)
    raw[o++] = r
    raw[o++] = g
    raw[o++] = b
  }
}

const png = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  chunk('IHDR', ihdr),
  chunk('IDAT', deflateSync(raw, { level: 9 })),
  chunk('IEND', Buffer.alloc(0)),
])

writeFileSync(OUT, png)
console.log(`wrote ${OUT} (${SIZE}x${SIZE}, ${png.length} bytes)`)
