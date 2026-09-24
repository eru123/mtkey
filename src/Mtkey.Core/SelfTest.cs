using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Mtkey.Core;

/// <summary>Known-answer tests and roundtrips, shared by `mtkey --selftest`
/// and the xunit suite. Defuse cross-language vectors come from
/// tools/gen-vectors.php, which produces them with the real PHP library.</summary>
public static class SelfTest
{
    public sealed record Case(string Name, bool Pass, string? Detail = null);

    public static List<Case> Run()
    {
        var cases = new List<Case>();
        void Check(string name, bool pass, string? detail = null) =>
            cases.Add(new Case(name, pass, detail));

        // ------------------------------------------------------ digests
        Check("md5(abc) known answer",
            Primitives.Hex(MD5.HashData(Primitives.Utf8.GetBytes("abc"))) ==
            "900150983cd24fb0d6963f7d28e17f72");
        Check("sha256(abc) known answer",
            Primitives.Hex(SHA256.HashData(Primitives.Utf8.GetBytes("abc"))) ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        Check("sha512(abc) known answer",
            Primitives.Hex(SHA512.HashData(Primitives.Utf8.GetBytes("abc"))).StartsWith(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"));
        Check("crc32(quick brown fox) known answer",
            Primitives.Crc32(Primitives.Utf8.GetBytes("The quick brown fox jumps over the lazy dog")) == 0x414FA339);

        // RFC 4231 test case 2
        var hmac = new HMACSHA256(Primitives.Utf8.GetBytes("Jefe"))
            .ComputeHash(Primitives.Utf8.GetBytes("what do ya want for nothing?"));
        Check("hmac-sha256 RFC 4231 vector",
            Primitives.Hex(hmac) == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

        // RFC 7914 section 11
        var pbkdf2 = Primitives.Pbkdf2Sha256(
            Primitives.Utf8.GetBytes("password"), Primitives.Utf8.GetBytes("salt"), 1, 32);
        Check("pbkdf2-sha256 RFC 7914 vector",
            Primitives.Hex(pbkdf2) == "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");

        // RFC 5869 test case 1
        var ikm = new byte[22];
        Array.Fill(ikm, (byte)0x0b);
        var okm = Primitives.HkdfSha256(ikm,
            Convert.FromHexString("000102030405060708090a0b0c"),
            Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9"),
            42);
        Check("hkdf-sha256 RFC 5869 vector",
            Primitives.Hex(okm) ==
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

        // ---------------------------------------------------- encodings
        Check("base64 RFC 4648 vector",
            Primitives.Base64(Primitives.Utf8.GetBytes("foobar")) == "Zm9vYmFy");
        Check("base32 RFC 4648 vector",
            Primitives.Base32(Primitives.Utf8.GetBytes("foobar")) == "MZXW6YTBOI");
        Check("base58 roundtrip incl. leading zeros",
            Primitives.Utf8.GetString(Primitives.Unbase58(
                Primitives.Base58(Primitives.Utf8.GetBytes("\0\0attack at dawn\0")))) == "\0\0attack at dawn\0");
        Check("base58 edge cases",
            Primitives.Base58(new byte[] { 0 }) == "1" &&
            Primitives.Base58(new byte[] { 0, 1 }) == "12" &&
            Primitives.Unbase58("1").SequenceEqual(new byte[] { 0 }));
        Check("url encoding",
            Uri.EscapeDataString("a b&c") == "a%20b%26c");
        Check("binary bits",
            Primitives.ToBinary(Primitives.Utf8.GetBytes("Hi")) == "01001000 01101001" &&
            Primitives.Utf8.GetString(Primitives.FromBinary("01001000 01101001")) == "Hi");
        Check("morse SOS",
            Run(new MorseMethod(), CipherDirection.Encode, "SOS").Output == "... --- ...");

        // ---------------------------------------------------- classical
        Check("caesar shift 3",
            Run(new CaesarMethod(), CipherDirection.Encode, "Caesar, 42!", shift: "3").Output == "Fdhvdu, 42!");
        Check("rot13",
            Run(new Rot13Method(), CipherDirection.Encode, "Hello").Output == "Uryyb");
        Check("atbash",
            Run(new AtbashMethod(), CipherDirection.Encode, "HELLO").Output == "SVOOL");
        Check("vigenere textbook vector",
            Run(new VigenereMethod(), CipherDirection.Encode, "ATTACKATDAWN", key: "LEMON").Output == "LXFOPVEFRNHR");
        Check("rail fence 3 rails",
            Run(new RailFenceMethod(), CipherDirection.Encode, "WEAREDISCOVEREDFLEEATONCE", rails: "3").Output
                .Replace(" ", "") == "WECRLTEERDSOEEFEAOCAIVDEN");
        Check("playfair wikipedia example",
            Run(new PlayfairMethod(), CipherDirection.Encode, "Hide the gold in the tree stump", key: "playfair example")
                .Output.Replace(" ", "") == "BMODZBXDNABEKUDMUIXMMOUVIF");
        Check("xor roundtrip",
            Primitives.Utf8.GetString(Primitives.Unhex(
                Run(new XorMethod(), CipherDirection.Encode, "attack at dawn", key: "secret").Output))
                is not null);

        // -------------------------------------------------------- modern
        var rsaPair = new RsaMethod().Generate("pub", new Dictionary<string, string>());
        var rsaRequest = new Dictionary<string, string>
        {
            ["pub"] = rsaPair["pub"],
            ["priv"] = rsaPair["priv"],
        };
        var rsaSecret = new RsaMethod().Process(new CipherRequest(CipherDirection.Encode, "small secret", rsaRequest));
        var rsaBack = new RsaMethod().Process(new CipherRequest(CipherDirection.Decode, rsaSecret.Output, rsaRequest));
        Check("rsa keypair roundtrip", rsaBack.Output == "small secret");

        var pairValidation = new RsaMethod().ValidateFields(rsaRequest);
        Check("rsa pair validation accepts", pairValidation.Overall.Contains("verified"));

        using (var other = RSA.Create(2048))
        {
            var mismatch = new RsaMethod().ValidateFields(new Dictionary<string, string>
            {
                ["pub"] = other.ExportSubjectPublicKeyInfoPem(),
                ["priv"] = rsaPair["priv"],
            });
            Check("rsa pair validation rejects mismatch", mismatch.Overall.Contains("NOT belong"));
        }

        var signResult = new RsaSignMethod().Process(new CipherRequest(CipherDirection.Encode, "the message", rsaRequest));
        var verify = new RsaSignMethod().Process(new CipherRequest(CipherDirection.Decode, "the message",
            new Dictionary<string, string>(rsaRequest) { ["sig"] = signResult.Output }));
        Check("rsa sign/verify", verify.Output.Contains("VALID"));
        var tampered = false;
        try
        {
            new RsaSignMethod().Process(new CipherRequest(CipherDirection.Decode, "the message!",
                new Dictionary<string, string>(rsaRequest) { ["sig"] = signResult.Output }));
        }
        catch (CipherException) { tampered = true; }
        Check("rsa sign detects tampering", tampered);

        Check("aes-cbc roundtrip",
            RoundtripBlockCipher("aes-cbc", "32bytesofpuregoldenkeymaterial!!", "0123456789abcdef"));
        Check("aes-gcm roundtrip + tamper detection",
            GcmRoundtrip("a secret worth protecting", "16bytesofpurekey", "nonce1234567"));

        // -------------------------------------------------------- tokens
        const string famousToken =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        var jwtResigned = Run(new JwtMethod(), CipherDirection.Encode,
            "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}",
            alg: "HS256", secret: "your-256-bit-secret");
        Check("jwt sign matches the jwt.io example", jwtResigned.Output == famousToken, jwtResigned.Output);
        var jwtDecoded = Run(new JwtMethod(), CipherDirection.Decode, famousToken,
            alg: "HS256", secret: "your-256-bit-secret");
        Check("jwt verify accepts the example", jwtDecoded.Note != null && jwtDecoded.Note.Contains("checks out"));
        var jwtBad = Run(new JwtMethod(), CipherDirection.Decode, famousToken,
            alg: "HS256", secret: "wrong-secret");
        Check("jwt verify rejects wrong secret", jwtBad.Warning != null);

        var jwksInspect = Run(new JwksMethod(), CipherDirection.Decode,
            "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"2011-04-29\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\"e\":\"AQAB\"}]}");
        Check("jwks parses the RFC 7517 example key",
            jwksInspect.Output.Contains("2048-bit") && jwksInspect.Output.Contains("BEGIN PUBLIC KEY"),
            jwksInspect.Output);

        var jwksBuilt = Run(new JwksMethod(), CipherDirection.Encode, "", priv: rsaPair["priv"], kid: "test-kid");
        var jwksBack = Run(new JwksMethod(), CipherDirection.Decode, jwksBuilt.Output);
        Check("jwks build/inspect roundtrip",
            jwksBack.Output.Contains("test-kid") && jwksBack.Output.Contains("BEGIN PRIVATE KEY"));

        // -------------------------------------------------------- defuse
        Check("defuse key save/load roundtrip", DefuseKeyRoundtrip());
        Check("defuse encrypt/decrypt roundtrip", DefuseEncryptRoundtrip());
        Check("defuse password roundtrip", DefusePasswordRoundtrip());
        Check("defuse tamper detection", DefuseTamper());
        Check("defuse cross-language vectors", DefuseCrossVectors(out var vectorDetail), vectorDetail);

        return cases;
    }

    public static CipherResult Run(CipherMethod method, CipherDirection dir, string input,
        params (string name, string value)[] fields)
    {
        var dict = fields.ToDictionary(f => f.name, f => f.value);
        return method.Process(new CipherRequest(dir, input, dict));
    }

    public static CipherResult Run(CipherMethod method, CipherDirection dir, string input,
        string? key = null, string? secret = null, string? alg = null, string? priv = null,
        string? kid = null, string? shift = null, string? rails = null)
    {
        var dict = new Dictionary<string, string>();
        if (key != null) dict["key"] = key;
        if (secret != null) dict["secret"] = secret;
        if (alg != null) dict["alg"] = alg;
        if (priv != null) dict["priv"] = priv;
        if (kid != null) dict["kid"] = kid;
        if (shift != null) dict["shift"] = shift;
        if (rails != null) dict["rails"] = rails;
        return method.Process(new CipherRequest(dir, input, dict));
    }

    private static bool DefuseKeyRoundtrip()
    {
        var key = DefuseCrypto.NewKey();
        var ascii = DefuseCrypto.SaveKeyAscii(key);
        return ascii.StartsWith("def00000") && DefuseCrypto.LoadKeyAscii(ascii).SequenceEqual(key);
    }

    private static bool DefuseEncryptRoundtrip()
    {
        var key = DefuseCrypto.NewKey();
        var ascii = DefuseCrypto.SaveKeyAscii(key);
        var ct = DefuseCrypto.Encrypt(Primitives.Utf8.GetBytes("roundtrip me 🎲"), key);
        return ct.StartsWith("def50200") &&
               Primitives.Utf8.GetString(DefuseCrypto.DecryptHex(ct, DefuseCrypto.LoadKeyAscii(ascii)))
               == "roundtrip me 🎲";
    }

    private static bool DefusePasswordRoundtrip()
    {
        var ct = DefuseCrypto.EncryptWithPassword(
            Primitives.Utf8.GetBytes("open sesame"), Primitives.Utf8.GetBytes("hunter2"));
        return Primitives.Utf8.GetString(
            DefuseCrypto.DecryptPasswordHex(ct, Primitives.Utf8.GetBytes("hunter2"))) == "open sesame";
    }

    private static bool DefuseTamper()
    {
        var key = DefuseCrypto.NewKey();
        var ct = DefuseCrypto.Encrypt(Primitives.Utf8.GetBytes("do not touch"), key);
        try
        {
            var hexBytes = Convert.FromHexString(ct);
            hexBytes[^1] ^= 0x01;
            DefuseCrypto.DecryptHex(Convert.ToHexString(hexBytes).ToLowerInvariant(), key);
            return false;
        }
        catch (CipherException)
        {
            return true;
        }
    }

    // ------------------------------------------------------------ vectors

    private static string? FindVectorsPath()
    {
        string[] candidates =
        {
            "vectors.json",
            Path.Combine(AppContext.BaseDirectory, "vectors.json"),
            Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "tests", "Mtkey.Tests", "vectors.json"),
            Path.Combine("tests", "Mtkey.Tests", "vectors.json"),
        };
        return candidates.FirstOrDefault(File.Exists);
    }

    private static bool DefuseCrossVectors(out string? detail)
    {
        var path = FindVectorsPath();
        if (path == null)
        {
            detail = "vectors.json not found. Run: php tools/gen-vectors.php > tests/Mtkey.Tests/vectors.json";
            return false;
        }

        try
        {
            var vectors = JsonDocument.Parse(File.ReadAllText(path)).RootElement;
            var ok = true;
            var notes = new List<string>();
            void Step(string name, bool pass, string note)
            {
                if (!pass) { ok = false; notes.Add($"{name}: {note}"); }
            }

            if (vectors.TryGetProperty("v2_key", out var v2Key))
            {
                var key = DefuseCrypto.LoadKeyAscii(v2Key.GetProperty("key_ascii").GetString()!);
                var pt = DefuseCrypto.DecryptHex(v2Key.GetProperty("ciphertext_hex").GetString()!, key);
                Step("php key ciphertext decrypts", Primitives.Utf8.GetString(pt) == v2Key.GetProperty("plaintext").GetString(),
                    "plaintext mismatch");
            }

            if (vectors.TryGetProperty("v2_password", out var v2Pass))
            {
                var pt = DefuseCrypto.DecryptPasswordHex(
                    v2Pass.GetProperty("ciphertext_hex").GetString()!,
                    Primitives.Utf8.GetBytes(v2Pass.GetProperty("password").GetString()!));
                Step("php password ciphertext decrypts",
                    Primitives.Utf8.GetString(pt) == v2Pass.GetProperty("plaintext").GetString(), "plaintext mismatch");
            }

            if (vectors.TryGetProperty("v2_kat", out var kat))
            {
                var ct = Primitives.Hex(DefuseCrypto.EncryptRaw(
                    Primitives.Utf8.GetBytes(kat.GetProperty("plaintext").GetString()!),
                    Convert.FromHexString(kat.GetProperty("key_hex").GetString()!),
                    Convert.FromHexString(kat.GetProperty("salt_hex").GetString()!),
                    Convert.FromHexString(kat.GetProperty("iv_hex").GetString()!)));
                Step("fixed salt/iv KAT matches php", ct == kat.GetProperty("ciphertext_hex").GetString(),
                    $"got {ct[..24]}..., want {kat.GetProperty("ciphertext_hex").GetString()![..24]}...");
            }

            if (vectors.TryGetProperty("v2_password_kat", out var pkat))
            {
                var ct = Primitives.Hex(DefuseCrypto.EncryptPasswordRaw(
                    Primitives.Utf8.GetBytes(pkat.GetProperty("plaintext").GetString()!),
                    Primitives.Utf8.GetBytes(pkat.GetProperty("password").GetString()!),
                    Convert.FromHexString(pkat.GetProperty("salt_hex").GetString()!),
                    Convert.FromHexString(pkat.GetProperty("iv_hex").GetString()!)));
                Step("password fixed salt/iv KAT matches php",
                    ct == pkat.GetProperty("ciphertext_hex").GetString(), "ciphertext mismatch");
            }

            if (vectors.TryGetProperty("key_wrap", out var wrap))
            {
                var unlocked = DefuseCrypto.UnlockProtectedKey(
                    wrap.GetProperty("protected_key_ascii").GetString()!,
                    wrap.GetProperty("password").GetString()!);
                Step("php password-protected key unlocks",
                    DefuseCrypto.SaveKeyAscii(unlocked) == wrap.GetProperty("inner_key_ascii").GetString(),
                    "unlocked key mismatch");
            }

            if (vectors.TryGetProperty("legacy_kat", out var legacy))
            {
                var pt = DefuseCrypto.LegacyDecrypt(
                    legacy.GetProperty("ciphertext_hex").GetString()!,
                    Convert.FromHexString(legacy.GetProperty("key_hex").GetString()!));
                Step("legacy v1 ciphertext decrypts",
                    Primitives.Utf8.GetString(pt) == legacy.GetProperty("plaintext").GetString(), "plaintext mismatch");
            }

            detail = ok ? $"all vector groups pass ({path})" : string.Join("; ", notes);
            return ok;
        }
        catch (Exception ex)
        {
            detail = $"vector file problem: {ex.Message}";
            return false;
        }
    }

    private static bool RoundtripBlockCipher(string id, string keyText, string ivText)
    {
        var method = Registry.Find(id)!;
        var fields = new Dictionary<string, string>
        {
            ["key"] = keyText,
            ["keyenc"] = "Text (UTF-8)",
            ["iv"] = ivText,
            ["ivenc"] = "Text (UTF-8)",
            ["out"] = "Base64",
        };
        var enc = method.Process(new CipherRequest(CipherDirection.Encode, "two way street 🚦", fields));
        var dec = method.Process(new CipherRequest(CipherDirection.Decode, enc.Output, fields));
        return dec.Output == "two way street 🚦";
    }

    private static bool GcmRoundtrip(string plaintext, string keyText, string nonceText)
    {
        var method = (BlockCipherMethod)Registry.Find("aes-gcm")!;
        var fields = new Dictionary<string, string>
        {
            ["key"] = keyText,
            ["keyenc"] = "Text (UTF-8)",
            ["iv"] = nonceText,
            ["ivenc"] = "Text (UTF-8)",
            ["out"] = "Base64",
        };
        var enc = method.Process(new CipherRequest(CipherDirection.Encode, plaintext, fields));
        var dec = method.Process(new CipherRequest(CipherDirection.Decode, enc.Output, fields));
        if (dec.Output != plaintext) return false;

        var tamperedBytes = Convert.FromBase64String(enc.Output);
        tamperedBytes[0] ^= 0xFF;
        try
        {
            method.Process(new CipherRequest(CipherDirection.Decode, Convert.ToBase64String(tamperedBytes), fields));
            return false;
        }
        catch (CipherException)
        {
            return true;
        }
    }
}
