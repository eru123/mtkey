# MTKey

That `def50200...` blob sitting in your `.env` file, or the JWT you paste into jwt.io for the fifth time this week, or the RSA key pair you need for class tomorrow. All of them are puzzles you can actually take apart, and this is the workbench for doing it.

MTKey is a free desktop app for macOS, Windows and Linux (built with Tauri 2, no account, fully offline) with 41 cipher, hash and token tools on board. Every method has a Wikipedia link next to it, a plain-language explanation of how it works, and a dice button that rolls fresh keys, salts and IVs for you. It was built for students, self-taught developers and the merely curious, not for auditors.

## Why you will keep it open

- **Learn while you poke.** Pick a cipher, read the two-paragraph explainer, click the link for the deep dive, then watch the output update live as you type. Base64, Caesar, Vigenère, Playfair, Rail fence, XOR, Morse, Base58 and friends.
- **Hashes that behave like hashes.** MD5 through SHA-512, SHA-3, HMAC, CRC-32, PBKDF2. One-way functions show a Hash button only, so the app itself teaches you there is no un-hashing.
- **Real modern crypto, safely sandboxed.** AES-GCM (tamper a byte and watch it refuse), AES-CBC, the deliberately dangerous AES-ECB penguin lesson, DES and 3DES as museum pieces, RSA-OAEP and RSA signatures.
- **RSA without the ceremony.** Click the dice on either key field and a matched public and private pair appears together, because they are born together. Paste your own keys and MTKey verifies on the spot whether they actually pair.
- **JWT and JWKS demystified.** Sign tokens with HS256/384/512 or RS256/384/512, decode any token into readable JSON, check signatures and expiry claims, and build or inspect JSON Web Key Sets.
- **It speaks PHP.** The full string-crypto surface of [defuse/php-encryption](https://github.com/defuse/php-encryption) is ported byte for byte, and so is the old mcrypt extension: Rijndael 128/192/256, Blowfish, DES, 3DES and RC4 with zero padding, plus the Laravel 3/4/5.0 `{iv, value, mac}` payloads. Ciphertexts that start with `def50200` decrypt here, and ciphertexts made here decrypt in PHP. Verified in both directions against the real library, not just against my own tests.

## The defuse compatibility promise

The four Defuse methods cover the library's string API: authenticated encryption with a stored key (`def00000...`), password encryption with PBKDF2 at 100,000 rounds, the password-protected key wrapper (`def10000...`), and a legacy reader for version 1 ciphertexts. The wire format is identical: `hex(DE F5 02 00 || salt || IV || AES-256-CTR || HMAC-SHA256)`. File streaming encryption is the same primitives applied per chunk, so it stayed out of a text tool.

To see the proof yourself, open the in-app self-test (the pill in the status bar). The last line checks ciphertexts produced by the actual PHP library, and the repo's CI regenerates those vectors from a fresh defuse checkout on every push.

## What is in the box

| Category | Methods |
| --- | --- |
| Encoding | Base64, Base32, Base58, Hex, URL, Binary, Morse |
| Classical | Caesar, ROT13, Atbash, Vigenère, Rail fence, Playfair, XOR |
| Hash | MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA-3-256, HMAC (MD5/SHA-1/SHA-256/SHA-512), CRC-32, PBKDF2 |
| Modern | AES-256-GCM, AES-CBC, AES-ECB, DES, Triple DES, RSA-OAEP, RSA signatures |
| PHP Interop | Defuse Authenticated (key), With password, Key tool (wrap/unlock), Legacy v1 decrypt, mcrypt (legacy PHP), Laravel Legacy Crypt |
| Tokens | JWT (sign/decode/verify), JWKS (build/inspect) |

## Download

Grab the installer for your platform from the [releases page](../../releases):

- Windows: `MTKey_2.1.0_x64-setup.exe` (NSIS installer)
- Linux (Debian/Ubuntu): `mtkey_2.1.0_amd64.deb`
- macOS: `MTKey_2.1.0_aarch64.dmg` / `MTKey_2.1.0_x64.dmg` (built by CI)

Everything runs offline. The app phones nobody home.

## Build it yourself

You need Node 20+, pnpm and a Rust toolchain. On Linux also install the Tauri system dependencies (see the [Tauri prerequisites](https://tauri.app/start/prerequisites/)).

```
git clone https://github.com/eru123/mtkey.git
cd mtkey
pnpm install
pnpm tauri dev      # run it
pnpm tauri build    # installers for your platform
```

Run the test suite (known-answer, roundtrip and cross-language checks, defuse and mcrypt):

```
pnpm test
```

For the full defuse cross-language suite, also clone the PHP library and regenerate the vectors, exactly like CI does:

```
git clone --depth 1 https://github.com/defuse/php-encryption.git ../defuse-ref
php tools/gen-vectors.php ../defuse-ref/src > tests/vectors.json
pnpm test
```

## A word on safety

This is a learning tool. It handles real algorithms with real keys, but you should not manage production secrets in a GUI text box. Nothing you type is sent anywhere; still, treat the app like a whiteboard, not a vault.

## License

[MIT](LICENSE), so you can read the code, fork it, and make it yours. That is rather the point.
