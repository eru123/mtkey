namespace Mtkey.Core;

/// <summary>The defuse/php-encryption suite, ported byte-for-byte so ciphertexts
/// interoperate with PHP apps using the library.</summary>
public abstract class DefuseMethodBase : CipherMethod
{
    public override string Category => "Defuse PHP";
    public override string WikiUrl => "https://github.com/defuse/php-encryption";
}

public sealed class DefuseKeyMethod : DefuseMethodBase
{
    public override string Id => "defuse-encrypt";
    public override string Name => "Defuse Authenticated (key)";
    public override string Blurb => "defuse/php-encryption v2 with a stored key. Ciphertexts start with def502.";
    public override string Learn =>
        "This is a byte-for-byte port of Defuse\\Crypto\\Crypto::encrypt, the authenticated " +
        "encryption used by many PHP applications. Inside: a random 32-byte salt and 16-byte " +
        "IV per message, HKDF splitting the key into an encryption key and an authentication " +
        "key, AES-256-CTR for secrecy and HMAC-SHA256 over everything for tamper detection. " +
        "Ciphertexts are plain lowercase hex, which is why they all start with def502 (the " +
        "hex of the version bytes DE F5 02 00). Strings encrypted by the PHP library load " +
        "here, and strings encrypted here load in PHP.";
    public override IReadOnlyList<string> Aliases => new[] { "defuse", "def502" };

    public override IReadOnlyList<FieldSpec> Fields { get; } = new[]
    {
        new FieldSpec
        {
            Name = "key",
            Label = "Defuse key",
            Secret = true,
            Placeholder = "def00000...",
            Hint = "The def00000... string from Key::saveToAsciiSafeString. Dice mints one.",
            Generator = GeneratorKind.DefuseKey,
        },
    };

    public override CipherResult Process(CipherRequest r)
    {
        var keyText = r.Field("key").Trim();
        if (keyText.Length == 0)
            throw new CipherException("Paste a defuse key (def00000...) or roll one with the dice.");
        var key = DefuseCrypto.LoadKeyAscii(keyText);

        if (r.Direction == CipherDirection.Encode)
            return new CipherResult(
                DefuseCrypto.Encrypt(Primitives.Utf8.GetBytes(r.Input), key),
                Note: "AES-256-CTR + HMAC-SHA256, fresh salt and IV every time.");

        var pt = DefuseCrypto.DecryptHex(r.Input, key);
        return new CipherResult(Primitives.Utf8.GetString(pt));
    }

    public override FieldValidation ValidateFields(IReadOnlyDictionary<string, string> values)
    {
        var result = new Dictionary<string, Validation>();
        var keyText = values.GetValueOrDefault("key", "").Trim();
        if (keyText.Length > 0)
        {
            result["key"] = DefuseCrypto.TryValidateKeyAscii(keyText, out var error)
                ? Validation.Good("Checksum OK, 32-byte key")
                : Validation.Bad(error);
        }
        return new FieldValidation(result, "");
    }
}

public sealed class DefusePasswordMethod : DefuseMethodBase
{
    public override string Id => "defuse-password";
    public override string Name => "Defuse With Password";
    public override string Blurb => "Same format, but the key is stretched from a human password.";
    public override string Learn =>
        "Crypto::encryptWithPassword runs the password through SHA-256, then PBKDF2-HMAC-SHA256 " +
        "100,000 times with the message salt, then HKDF, before the same AES-CTR + HMAC core " +
        "runs. The point of the slow KDF is cost: every wrong password guess an attacker makes " +
        "pays the 100k iterations too. Compare that with using a password directly as an AES " +
        "key, where each guess is one fast AES operation.";
    public override IReadOnlyList<string> Aliases => new[] { "defuse" };

    public override IReadOnlyList<FieldSpec> Fields { get; } = new[]
    {
        new FieldSpec
        {
            Name = "password",
            Label = "Password",
            Secret = true,
            Placeholder = "correct horse battery staple",
            Hint = "Slow-derived (PBKDF2, 100k rounds) into the encryption and auth keys.",
            Generator = GeneratorKind.Password,
        },
    };

    public override CipherResult Process(CipherRequest r)
    {
        var password = r.Field("password");
        if (password.Length == 0)
            throw new CipherException("A password is needed for this method.");

        if (r.Direction == CipherDirection.Encode)
            return new CipherResult(
                DefuseCrypto.EncryptWithPassword(Primitives.Utf8.GetBytes(r.Input), Primitives.Utf8.GetBytes(password)),
                Note: "PBKDF2 100,000 rounds + HKDF + AES-256-CTR + HMAC-SHA256.");

        var pt = DefuseCrypto.DecryptPasswordHex(r.Input, Primitives.Utf8.GetBytes(password));
        return new CipherResult(Primitives.Utf8.GetString(pt));
    }
}

public sealed class DefuseKeyToolMethod : DefuseMethodBase
{
    public override string Id => "defuse-key";
    public override string Name => "Defuse Key Tool";
    public override string Blurb => "Generate, protect and unlock def00000 keys, including def10000 password-wrapped ones.";
    public override string Learn =>
        "The PHP library stores keys as hex with a built-in SHA-256 checksum (def00000...). " +
        "KeyProtectedByPassword wraps a real key inside password encryption, giving a " +
        "def10000... string you can keep on a web server: the app can unlock it at runtime " +
        "with the password, but a backup leak alone does not reveal the key. Encode here " +
        "mints or wraps keys; Decode unwraps a def10000 string back into its def00000 key.";
    public override IReadOnlyList<string> Aliases => new[] { "defuse", "keygen", "def10000" };

    public override string EncodeLabel => "Generate / wrap";
    public override string DecodeLabel => "Unlock";

    public override IReadOnlyList<FieldSpec> Fields { get; } = new[]
    {
        new FieldSpec
        {
            Name = "mode",
            Label = "Action",
            Kind = FieldKind.Dropdown,
            Options = new[] { "New raw key (def00000)", "Wrap key with password (def10000)" },
            Default = "New raw key (def00000)",
            Hint = "Wrapping needs the password below; a fresh random key is minted when its field is empty.",
        },
        new FieldSpec
        {
            Name = "key",
            Label = "Raw key",
            Kind = FieldKind.Multiline,
            Secret = true,
            Placeholder = "def00000... (leave empty to mint a new one)",
            Hint = "For wrapping: the key to protect. Empty means generate fresh.",
            Generator = GeneratorKind.DefuseKey,
        },
        new FieldSpec
        {
            Name = "password",
            Label = "Password",
            Secret = true,
            Placeholder = "only needed for wrapping and unlocking",
            Generator = GeneratorKind.Password,
        },
    };

    public override CipherResult Process(CipherRequest r)
    {
        if (r.Direction == CipherDirection.Encode)
        {
            var mode = r.Field("mode");
            if (mode.StartsWith("Wrap"))
            {
                var password = r.Field("password");
                if (password.Length == 0)
                    throw new CipherException("Wrapping needs a password.");
                var keyText = r.Field("key").Trim();
                var key = keyText.Length > 0 ? DefuseCrypto.LoadKeyAscii(keyText) : DefuseCrypto.NewKey();
                return new CipherResult(
                    DefuseCrypto.WrapProtected(key, password),
                    Note: keyText.Length > 0
                        ? "Wrapped your key. Store the def10000 string, keep the password elsewhere."
                        : "Minted a fresh key and wrapped it. Save the def10000 string AND the password.");
            }

            var keyText2 = r.Field("key").Trim();
            var key2 = keyText2.Length > 0 ? DefuseCrypto.LoadKeyAscii(keyText2) : DefuseCrypto.NewKey();
            return new CipherResult(
                DefuseCrypto.SaveKeyAscii(key2),
                Note: "Share only with systems that need to encrypt or decrypt.");
        }
        else
        {
            var wrapped = r.Input.Trim();
            if (wrapped.Length == 0)
                throw new CipherException("Paste a def10000... password-protected key to unlock.");
            var password = r.Field("password");
            if (password.Length == 0)
                throw new CipherException("Unlocking needs the password it was wrapped with.");
            var raw = DefuseCrypto.UnlockProtectedKey(wrapped, password);
            return new CipherResult(
                DefuseCrypto.SaveKeyAscii(raw),
                Note: "Unlocked. This def00000 key is now bare, handle it accordingly.");
        }
    }
}

public sealed class DefuseLegacyMethod : DefuseMethodBase
{
    public override string Id => "defuse-legacy";
    public override string Name => "Defuse v1 (legacy decrypt)";
    public override string Blurb => "Reads ciphertext from version 1.x of the library. Decrypt only.";
    public override string Learn =>
        "Version 1 of defuse/php-encryption used AES-128-CBC with HMAC-SHA256 and put the " +
        "MAC at the FRONT of the string, before the IV. Version 2 switched to CTR mode, " +
        "added per-message salts and moved the MAC to the end. This method exists so old " +
        "data can still be read; it will never produce new v1 ciphertext.";
    public override bool TwoWay => false;
    public override string EncodeLabel => "n/a";
    public override string DecodeLabel => "Decrypt";

    public override IReadOnlyList<FieldSpec> Fields { get; } = new[]
    {
        new FieldSpec
        {
            Name = "key",
            Label = "Raw v1 key (hex)",
            Secret = true,
            Placeholder = "32 hex digits = 16 bytes",
            Hint = "v1 used 128-bit keys, entered here as 32 hex characters.",
            Generator = GeneratorKind.HexBytes,
            GeneratorSize = 16,
        },
    };

    public override CipherResult Process(CipherRequest r)
    {
        var key = Primitives.Unhex(r.Field("key").Trim());
        var pt = DefuseCrypto.LegacyDecrypt(r.Input, key);
        return new CipherResult(Primitives.Utf8.GetString(pt));
    }
}

public static class DefuseMethods
{
    public static IEnumerable<CipherMethod> All()
    {
        yield return new DefuseKeyMethod();
        yield return new DefusePasswordMethod();
        yield return new DefuseKeyToolMethod();
        yield return new DefuseLegacyMethod();
    }
}
