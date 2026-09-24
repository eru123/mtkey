using System.Security.Cryptography;

namespace Mtkey.Core;

/// <summary>Shared plumbing for key/IV block ciphers: field layout, key
/// decoding and friendly errors.</summary>
public sealed class BlockCipherMethod : CipherMethod
{
    private readonly string id, name, blurb, learn, wiki;
    private readonly string algorithm;      // AES, DES, TripleDES
    private readonly int[] keySizes;        // valid key lengths in bytes
    private readonly int ivSize;
    private readonly CipherMode mode;       // CBC or ECB
    private readonly bool gcm;
    private readonly string? warning;
    private readonly string[] aliases;

    private static readonly string[] KeyEncodings = { "Hex", "Base64", "Text (UTF-8)" };
    private static readonly string[] OutputEncodings = { "Base64", "Hex" };

    public BlockCipherMethod(string id, string name, string blurb, string learn, string wiki,
        string algorithm, int[] keySizes, int ivSize, CipherMode mode, bool gcm = false,
        string? warning = null, string[]? aliases = null)
    {
        this.id = id; this.name = name; this.blurb = blurb; this.learn = learn;
        this.wiki = wiki; this.algorithm = algorithm; this.keySizes = keySizes;
        this.ivSize = ivSize; this.mode = mode; this.gcm = gcm;
        this.warning = warning; this.aliases = aliases ?? Array.Empty<string>();
    }

    public override string Id => id;
    public override string Name => name;
    public override string Blurb => blurb;
    public override string Learn => learn;
    public override string WikiUrl => wiki;
    public override IReadOnlyList<string> Aliases => aliases;
    public override string Category => "Modern";

    public override IReadOnlyList<FieldSpec> Fields
    {
        get
        {
            var list = new List<FieldSpec>
            {
                new()
                {
                    Name = "key",
                    Label = "Key",
                    Secret = true,
                    Placeholder = string.Join(" / ", keySizes.Select(b => $"{b} bytes")),
                    Hint = $"{string.Join(", ", keySizes.Select(b => b * 8))}-bit. {string.Join(", ", keySizes)} bytes.",
                    Generator = GeneratorKind.HexBytes,
                    GeneratorSize = keySizes[^1],
                },
                new()
                {
                    Name = "keyenc",
                    Label = "Key encoding",
                    Kind = FieldKind.Dropdown,
                    Options = KeyEncodings,
                    Default = "Hex",
                },
            };
            if (ivSize > 0)
            {
                list.Add(new FieldSpec
                {
                    Name = "iv",
                    Label = gcm ? "Nonce" : "IV",
                    Placeholder = gcm ? "12 bytes" : $"{ivSize} bytes",
                    Hint = gcm
                        ? "Number used ONCE. Reusing a nonce with the same key breaks GCM completely."
                        : "Initialisation vector. Different every message, not secret.",
                    Generator = GeneratorKind.HexBytes,
                    GeneratorSize = ivSize,
                });
                list.Add(new FieldSpec
                {
                    Name = "ivenc",
                    Label = gcm ? "Nonce encoding" : "IV encoding",
                    Kind = FieldKind.Dropdown,
                    Options = KeyEncodings,
                    Default = "Hex",
                });
            }
            list.Add(new FieldSpec
            {
                Name = "out",
                Label = "Output",
                Kind = FieldKind.Dropdown,
                Options = OutputEncodings,
                Default = "Base64",
            });
            return list;
        }
    }

    public override CipherResult Process(CipherRequest r)
    {
        var key = Primitives.DecodeKeyMaterial(r.Field("key"), r.Field("keyenc"));
        if (!keySizes.Contains(key.Length))
            throw new CipherException(
                $"{Name} needs a {string.Join(" or ", keySizes.Select(s => s * 8))}-bit key " +
                $"({string.Join("/", keySizes)} bytes). Got {key.Length}.");

        if (gcm)
            return ProcessGcm(r, key);

        var iv = Array.Empty<byte>();
        string? note = null;
        if (ivSize > 0)
        {
            var ivText = r.Field("iv").Trim();
            if (r.Direction == CipherDirection.Encode && ivText.Length == 0)
            {
                iv = RandomNumberGenerator.GetBytes(ivSize);
                note = $"No IV given, so a random one was used ({Primitives.Hex(iv)}). " +
                       "Copy it if you want to decrypt later.";
            }
            else
            {
                iv = Primitives.DecodeKeyMaterial(ivText, r.Field("ivenc"));
                if (iv.Length != ivSize)
                    throw new CipherException($"The IV must be exactly {ivSize} bytes, got {iv.Length}.");
            }
        }

        var outputEncoding = r.Field("out");
        try
        {
            if (r.Direction == CipherDirection.Encode)
            {
                var ct = Transform(Primitives.Utf8.GetBytes(r.Input), key, iv, encrypt: true);
                return new CipherResult(Render(ct, outputEncoding), note, warning);
            }
            var pt = Transform(DecodeInput(r.Input, outputEncoding), key, iv, encrypt: false);
            return new CipherResult(Primitives.Utf8.GetString(pt), null, warning);
        }
        catch (CipherException) { throw; }
        catch (CryptographicException)
        {
            throw new CipherException("Decryption failed. Check the key, the IV and that the " +
                "input is complete; wrong padding almost always means a wrong key.");
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException)
        {
            throw new CipherException($"The input is not valid {outputEncoding}.");
        }
    }

    private CipherResult ProcessGcm(CipherRequest r, byte[] key)
    {
        var nonceText = r.Field("iv").Trim();
        if (nonceText.Length == 0)
            throw new CipherException("GCM needs a nonce. The dice button rolls a safe one.");
        var nonce = Primitives.DecodeKeyMaterial(nonceText, r.Field("ivenc"));
        if (nonce.Length != 12)
            throw new CipherException($"The nonce must be 12 bytes, got {nonce.Length}.");

        var outputEncoding = r.Field("out");
        if (r.Direction == CipherDirection.Encode)
        {
            var ct = new byte[Primitives.Utf8.GetBytes(r.Input).Length];
            var tag = new byte[16];
            using var aesGcm = new AesGcm(key, 16);
            aesGcm.Encrypt(nonce, Primitives.Utf8.GetBytes(r.Input), ct, tag);
            var combined = new byte[ct.Length + tag.Length];
            ct.CopyTo(combined, 0);
            tag.CopyTo(combined, ct.Length);
            return new CipherResult(Render(combined, outputEncoding),
                "Ciphertext with the 16-byte tag appended.",
                "Never reuse a nonce with the same key. GCM nonce reuse leaks the key.");
        }
        else
        {
            var data = DecodeInput(r.Input, outputEncoding);
            if (data.Length < 16)
                throw new CipherException("Input too short: GCM output carries at least a 16-byte tag.");
            var ct = data[..^16];
            var tag = data[^16..];
            var pt = new byte[ct.Length];
            try
            {
                using var aesGcm = new AesGcm(key, 16);
                aesGcm.Decrypt(nonce, ct, tag, pt);
            }
            catch (CryptographicException)
            {
                throw new CipherException("Authentication failed. Wrong key, wrong nonce, or the " +
                    "ciphertext was tampered with. That is GCM doing its job.");
            }
            return new CipherResult(Primitives.Utf8.GetString(pt));
        }
    }

    private byte[] Transform(byte[] data, byte[] key, byte[] iv, bool encrypt)
    {
        using var alg = algorithm switch
        {
            "DES" => (SymmetricAlgorithm)DES.Create(),
            "TripleDES" => TripleDES.Create(),
            _ => Aes.Create(),
        };
        alg.Mode = mode == CipherMode.ECB ? CipherMode.ECB : mode;
        alg.Padding = PaddingMode.PKCS7;
        alg.Key = key;
        if (iv.Length > 0)
            alg.IV = iv;
        using var xform = encrypt ? alg.CreateEncryptor() : alg.CreateDecryptor();
        return xform.TransformFinalBlock(data, 0, data.Length);
    }

    private static byte[] DecodeInput(string input, string encoding) =>
        encoding == "Hex" ? Primitives.Unhex(input) : Primitives.Unbase64(input);

    private static string Render(byte[] bytes, string encoding) =>
        encoding == "Hex" ? Primitives.Hex(bytes) : Primitives.Base64(bytes);
}

public sealed class RsaMethod : CipherMethod
{
    public override string Id => "rsa";
    public override string Name => "RSA Encrypt (OAEP)";
    public override string Blurb => "Public key encrypts, only the private key reads it back.";
    public override string Learn =>
        "RSA is asymmetric: what one key locks, only its partner opens. You hand out the " +
        "public key to everyone and keep the private one offline. Encrypting to a person " +
        "means using THEIR public key. Real protocols never RSA-encrypt the message itself, " +
        "only a fresh AES key (hybrid encryption), because RSA can only encrypt a few " +
        "hundred bytes and is slow. This tool uses OAEP padding with SHA-256, the safe way.";
    public override string WikiUrl => "https://en.wikipedia.org/wiki/RSA_(cryptosystem)";
    public override string Category => "Modern";

    public override IReadOnlyList<FieldSpec> Fields { get; } = new[]
    {
        new FieldSpec
        {
            Name = "pub",
            Label = "Public key (PEM)",
            Kind = FieldKind.Multiline,
            Placeholder = "-----BEGIN PUBLIC KEY-----",
            Hint = "Used to encrypt. Click the dice to generate a matched pair.",
            Generator = GeneratorKind.RsaKeyPair,
        },
        new FieldSpec
        {
            Name = "priv",
            Label = "Private key (PEM)",
            Kind = FieldKind.Multiline,
            Secret = true,
            Placeholder = "-----BEGIN PRIVATE KEY-----",
            Hint = "Used to decrypt. The dice fills both keys together.",
            Generator = GeneratorKind.RsaKeyPair,
        },
        new FieldSpec
        {
            Name = "bits",
            Label = "Key size",
            Kind = FieldKind.Dropdown,
            Options = new[] { "2048", "3072", "4096" },
            Default = "2048",
        },
    };

    public override CipherResult Process(CipherRequest r)
    {
        if (r.Direction == CipherDirection.Encode)
        {
            using var rsa = ImportForEncrypt(r);
            var data = Primitives.Utf8.GetBytes(r.Input);
            try
            {
                var ct = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
                return new CipherResult(Primitives.Base64(ct),
                    Note: $"RSA-{rsa.KeySize} with OAEP/SHA-256 padding.");
            }
            catch (CryptographicException)
            {
                throw new CipherException(
                    $"The message is too long for RSA-{rsa.KeySize} with OAEP " +
                    $"(limit is {(rsa.KeySize / 8) - 62} bytes). RSA is for small payloads; " +
                    "use it to wrap an AES key in real systems.");
            }
        }
        else
        {
            var priv = r.Field("priv").Trim();
            if (priv.Length == 0)
                throw new CipherException("Decryption needs the private key.");
            using var rsa = ImportKey(priv, "private");
            byte[] ct;
            try
            {
                ct = Primitives.Unbase64(r.Input);
            }
            catch (CipherException)
            {
                throw new CipherException("The input is not valid Base64 ciphertext.");
            }
            try
            {
                var pt = rsa.Decrypt(ct, RSAEncryptionPadding.OaepSHA256);
                return new CipherResult(Primitives.Utf8.GetString(pt));
            }
            catch (CryptographicException)
            {
                throw new CipherException("Decryption failed. This ciphertext does not match " +
                    "this key, or it was not encrypted with OAEP/SHA-256.");
            }
        }
    }

    internal static RSA ImportForEncrypt(CipherRequest r)
    {
        var pub = r.Field("pub").Trim();
        if (pub.Length > 0)
            return ImportKey(pub, "public");
        var priv = r.Field("priv").Trim();
        if (priv.Length > 0)
            return ImportKey(priv, "private");
        throw new CipherException("Encryption needs the public key (or a private key, whose public half will be used).");
    }

    internal static RSA ImportKey(string pem, string what)
    {
        try
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            return rsa;
        }
        catch (ArgumentException)
        {
            throw new CipherException($"That does not look like a valid {what} key in PEM format.");
        }
    }

    /// <summary>Extracts the public half from a private PEM when needed.</summary>
    internal static byte[] PublicModulus(RSA rsa) => rsa.ExportParameters(false).Modulus!;

    public override FieldValidation ValidateFields(IReadOnlyDictionary<string, string> values)
    {
        var result = new Dictionary<string, Validation>();
        var overall = "";
        RSA? pub = null, priv = null;

        var pubText = values.GetValueOrDefault("pub", "").Trim();
        var privText = values.GetValueOrDefault("priv", "").Trim();
        if (pubText.Length > 0)
        {
            try { pub = ImportKey(pubText, "public"); result["pub"] = Validation.Good($"Valid public key, {pub.KeySize}-bit"); }
            catch (CipherException ex) { result["pub"] = Validation.Bad(ex.Message); }
        }
        if (privText.Length > 0)
        {
            try { priv = ImportKey(privText, "private"); result["priv"] = Validation.Good($"Valid private key, {priv.KeySize}-bit"); }
            catch (CipherException ex) { result["priv"] = Validation.Bad(ex.Message); }
        }

        if (pub is not null && priv is not null)
        {
            bool match;
            try
            {
                var probe = pub.Encrypt(new byte[] { 1, 2, 3 }, RSAEncryptionPadding.OaepSHA256);
                match = priv.Decrypt(probe, RSAEncryptionPadding.OaepSHA256)
                    .SequenceEqual(new byte[] { 1, 2, 3 });
            }
            catch (CryptographicException)
            {
                // Windows CNG reports "not this key's ciphertext" as a
                // parameter error rather than a padding failure.
                match = false;
            }
            overall = match
                ? "Key pair verified: the private key unlocks the public key."
                : "These two keys do NOT belong to the same pair.";
            if (!match)
            {
                result["pub"] = Validation.Bad("Does not pair with the private key below");
                result["priv"] = Validation.Bad("Does not pair with the public key above");
            }
        }
        else if (pub is not null || priv is not null)
        {
            overall = "One key present. The dice generates a matched pair in one click.";
        }
        return new FieldValidation(result, overall);
    }

    public override IReadOnlyDictionary<string, string> Generate(
        string field, IReadOnlyDictionary<string, string> current)
    {
        if (!int.TryParse(current.GetValueOrDefault("bits", "2048"), out var bits))
            bits = 2048;
        using var rsa = RSA.Create(bits);
        return new Dictionary<string, string>
        {
            ["pub"] = rsa.ExportSubjectPublicKeyInfoPem(),
            ["priv"] = rsa.ExportPkcs8PrivateKeyPem(),
        };
    }
}

public sealed class RsaSignMethod : CipherMethod
{
    public override string Id => "rsa-sign";
    public override string Name => "RSA Signature";
    public override string Blurb => "Sign with the private key, anyone verifies with the public one.";
    public override string Learn =>
        "A signature flips RSA around: the private key holder signs, and every holder of the " +
        "public key can check the message really came from them and was not altered. " +
        "Certificates, JWTs (RS256) and signed software updates all work this way. " +
        "Encryption gives secrecy, signatures give authenticity: related ideas, opposite keys.";
    public override string WikiUrl => "https://en.wikipedia.org/wiki/Digital_signature";
    public override string Category => "Modern";
    public override string EncodeLabel => "Sign";
    public override string DecodeLabel => "Verify";

    public override IReadOnlyList<FieldSpec> Fields { get; } = new[]
    {
        new FieldSpec
        {
            Name = "priv",
            Label = "Private key (PEM)",
            Kind = FieldKind.Multiline,
            Secret = true,
            Placeholder = "-----BEGIN PRIVATE KEY-----",
            Hint = "Signs the message. Dice generates a matched pair.",
            Generator = GeneratorKind.RsaKeyPair,
        },
        new FieldSpec
        {
            Name = "pub",
            Label = "Public key (PEM)",
            Kind = FieldKind.Multiline,
            Placeholder = "-----BEGIN PUBLIC KEY-----",
            Hint = "Verifies the signature.",
            Generator = GeneratorKind.RsaKeyPair,
        },
        new FieldSpec
        {
            Name = "sig",
            Label = "Signature (Base64)",
            Kind = FieldKind.Multiline,
            Placeholder = "Paste the signature here to verify...",
            Hint = "Produced by Sign, checked by Verify.",
        },
        new FieldSpec
        {
            Name = "bits",
            Label = "Key size",
            Kind = FieldKind.Dropdown,
            Options = new[] { "2048", "3072", "4096" },
            Default = "2048",
        },
    };

    public override CipherResult Process(CipherRequest r)
    {
        if (r.Direction == CipherDirection.Encode)
        {
            var priv = r.Field("priv").Trim();
            if (priv.Length == 0)
                throw new CipherException("Signing needs the private key.");
            using var rsa = RsaMethod.ImportKey(priv, "private");
            var sig = rsa.SignData(Primitives.Utf8.GetBytes(r.Input),
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return new CipherResult(Primitives.Base64(sig),
                Note: $"Signed with RSA-{rsa.KeySize} / SHA-256 / PKCS#1 v1.5 (the RS256 recipe).");
        }
        else
        {
            var pub = r.Field("pub").Trim();
            if (pub.Length == 0)
                throw new CipherException("Verifying needs the public key.");
            var sigText = r.Field("sig").Trim();
            if (sigText.Length == 0)
                throw new CipherException("Paste the signature to verify.");
            using var rsa = RsaMethod.ImportKey(pub, "public");
            var sig = Primitives.Unbase64(sigText);
            var ok = rsa.VerifyData(Primitives.Utf8.GetBytes(r.Input), sig,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            if (!ok)
                throw new CipherException("Signature INVALID. The message, the signature or " +
                    "the key does not match, or the text was altered after signing.");
            return new CipherResult("Signature is VALID.",
                Note: $"Verified with RSA-{rsa.KeySize} / SHA-256. The message is authentic and unaltered.");
        }
    }

    public override IReadOnlyDictionary<string, string> Generate(
        string field, IReadOnlyDictionary<string, string> current)
    {
        if (!int.TryParse(current.GetValueOrDefault("bits", "2048"), out var bits))
            bits = 2048;
        using var rsa = RSA.Create(bits);
        return new Dictionary<string, string>
        {
            ["pub"] = rsa.ExportSubjectPublicKeyInfoPem(),
            ["priv"] = rsa.ExportPkcs8PrivateKeyPem(),
        };
    }

    public override FieldValidation ValidateFields(IReadOnlyDictionary<string, string> values)
    {
        var result = new Dictionary<string, Validation>();
        var priv = values.GetValueOrDefault("priv", "").Trim();
        var pub = values.GetValueOrDefault("pub", "").Trim();
        if (priv.Length > 0)
        {
            try { using var k = RsaMethod.ImportKey(priv, "private"); result["priv"] = Validation.Good($"Valid private key, {k.KeySize}-bit"); }
            catch (CipherException ex) { result["priv"] = Validation.Bad(ex.Message); }
        }
        if (pub.Length > 0)
        {
            try { using var k = RsaMethod.ImportKey(pub, "public"); result["pub"] = Validation.Good($"Valid public key, {k.KeySize}-bit"); }
            catch (CipherException ex) { result["pub"] = Validation.Bad(ex.Message); }
        }
        return new FieldValidation(result, "");
    }
}

public static class ModernMethods
{
    public static IEnumerable<CipherMethod> All()
    {
        yield return new BlockCipherMethod(
            "aes-gcm", "AES-256-GCM", "Authenticated encryption: tampering is detected, not just decrypted wrong.",
            "GCM encrypts and authenticates in one pass with AES under the hood. The tag at the " +
            "end is a fingerprint of key, nonce and ciphertext together: change one bit and " +
            "decryption refuses. This is the mode behind TLS 1.3, encrypted SQLite databases " +
            "and age/ OpenSSL modern defaults. The one rule: a nonce must never repeat under " +
            "the same key.",
            "https://en.wikipedia.org/wiki/Galois/Counter_Mode",
            "AES", new[] { 16, 24, 32 }, 12, CipherMode.CBC, gcm: true, aliases: new[] { "gcm" });

        yield return new BlockCipherMethod(
            "aes-cbc", "AES-CBC", "Classic block chaining with PKCS#7 padding. No built-in integrity.",
            "CBC XORs each plaintext block with the previous ciphertext block before " +
            "encrypting, so identical blocks no longer produce identical output. The IV " +
            "randomises the first block. Padding Oracle attacks taught the industry that CBC " +
            "without a MAC is dangerous: always pair it with HMAC or move to GCM.",
            "https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation",
            "AES", new[] { 16, 24, 32 }, 16, CipherMode.CBC, aliases: new[] { "aes" });

        yield return new BlockCipherMethod(
            "aes-ecb", "AES-ECB", "Every block encrypted identically. A living lesson in why modes matter.",
            "ECB encrypts each 16-byte block independently with no chaining at all, so two " +
            "identical blocks of plaintext produce identical ciphertext. The famous ECB " +
            "penguin: encrypt the Linux penguin image in ECB and you can still see the penguin. " +
            "Try encoding 'attack at dawn... attack at dawn...' with a repeated 16-byte " +
            "pattern and watch the ciphertext repeat too.",
            "https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation",
            "AES", new[] { 16, 24, 32 }, 0, CipherMode.ECB,
            warning: "ECB is here for learning why it is dangerous. Never use it for real data.",
            aliases: new[] { "aes" });

        yield return new BlockCipherMethod(
            "des", "DES", "56-bit cipher from 1977. Broken by brute force in 1998.",
            "DES was the first public crypto standard, small enough that the EFF built a " +
            "machine (Deep Crack, $250,000) that found a DES key in 56 hours in 1998. " +
            "Its 56-bit key space is now searched in hours on cloud GPUs. It is included " +
            "here so you can inspect a piece of history, not to protect anything.",
            "https://en.wikipedia.org/wiki/Data_Encryption_Standard",
            "DES", new[] { 8 }, 8, CipherMode.CBC,
            warning: "DES is broken. Educational use only.");

        yield return new BlockCipherMethod(
            "3des", "Triple DES", "DES applied three times to stretch the key. Being retired.",
            "Triple DES runs DES three times (encrypt, decrypt, encrypt) with two or three " +
            "keys, giving 112-bit strength from a 56-bit cipher. It kept banks and payment " +
            "systems running for decades, but it is slow and was formally disallowed for " +
            "new designs by NIST in 2023.",
            "https://en.wikipedia.org/wiki/Triple_DES",
            "TripleDES", new[] { 16, 24 }, 8, CipherMode.CBC,
            warning: "3DES is deprecated. Educational use only.",
            aliases: new[] { "tripledes", "3des" });

        yield return new RsaMethod();
        yield return new RsaSignMethod();
    }
}
