/** RC4 (Rivest, 1987), sold to the PHP world as MCRYPT_ARCFOUR / "stream".
 * Keystream generator only; the caller XORs. Educational rescue of legacy
 * data only - never use RC4 for anything new. Pinned by the classic
 * published vectors and the real-mcrypt suite. */
export function rc4Crypt(key: Uint8Array, data: Uint8Array): Uint8Array {
  if (key.length === 0) throw new Error('RC4 needs a key.')
  const s = new Uint8Array(256)
  for (let i = 0; i < 256; i++) s[i] = i
  let j = 0
  for (let i = 0; i < 256; i++) {
    j = (j + s[i] + key[i % key.length]) & 0xff
    const tmp = s[i]
    s[i] = s[j]
    s[j] = tmp
  }
  const out = new Uint8Array(data.length)
  let i = 0
  j = 0
  for (let n = 0; n < data.length; n++) {
    i = (i + 1) & 0xff
    j = (j + s[i]) & 0xff
    const tmp = s[i]
    s[i] = s[j]
    s[j] = tmp
    out[n] = data[n] ^ s[(s[i] + s[j]) & 0xff]
  }
  return out
}
