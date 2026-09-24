using System.Security.Cryptography;

namespace Mtkey.Core;

/// <summary>
/// A faithful C# port of the string-encryption core of defuse/php-encryption
/// (https://github.com/defuse/php-encryption), verified against the PHP
/// library with generated cross-language test vectors.
///
/// Wire format (v2, master as of 2025):
///   hex( DE F5 02 00 || salt(32) || IV(16) || AES-256-CTR ciphertext || HMAC-SHA256(32) )
/// so every ciphertext string starts with "def50200". The HMAC covers
/// everything before it. Keys are stored as
///   hex( DE F0 00 00 || 32 raw bytes || SHA-256 checksum )
/// which is why they start with "def00000".
/// </summary>
public static class DefuseCrypto
{
    public const int HeaderVersionSize = 4;
    public const int MinimumCiphertextSize = 84;   // header + salt + iv + mac, empty plaintext
    public const int BlockSize = 16;
    public const int KeySize = 32;
    public const int SaltSize = 32;
    public const int MacSize = 32;
    public const int Pbkdf2Iterations = 100_000;

    private static readonly byte[] CiphertextHeader = { 0xDE, 0xF5, 0x02, 0x00 };
    private static readonly byte[] KeyHeader = { 0xDE, 0xF0, 0x00, 0x00 };
    private static readonly byte[] ProtectedKeyHeader = { 0xDE, 0xF1, 0x00, 0x00 };

    private const string EncryptionInfo = "DefusePHP|V2|KeyForEncryption";
    private const string AuthenticationInfo = "DefusePHP|V2|KeyForAuthentication";
    private const string LegacyEncryptionInfo = "DefusePHP|KeyForEncryption";
    private const string LegacyAuthenticationInfo = "DefusePHP|KeyForAuthentication";

    private static readonly byte[] LegacyEncryptionInfoBytes = System.Text.Encoding.ASCII.GetBytes(LegacyEncryptionInfo);
    private static readonly byte[] LegacyAuthenticationInfoBytes = System.Text.Encoding.ASCII.GetBytes(LegacyAuthenticationInfo);

    // ------------------------------------------------------------ keys

    public static byte[] NewKey() => RandomNumberGenerator.GetBytes(KeySize);

    /// <summary>A ready-to-paste def00000... key string.</summary>
    public static string NewKeyAscii() => SaveKeyAscii(NewKey());

    public static string SaveKeyAscii(byte[] rawKey)
    {
        if (rawKey.Length != KeySize)
            throw new CipherException("A defuse key must be exactly 32 bytes.");
        return Primitives.Hex(WrapChecksummed(KeyHeader, rawKey));
    }

    /// <summary>Accepts trailing whitespace the way the PHP loader does, and
    /// verifies the embedded SHA-256 checksum.</summary>
    public static byte[] LoadKeyAscii(string saved)
    {
        var bytes = LoadChecksummed(KeyHeader, saved, "key");
        if (bytes.Length != KeySize)
            throw new CipherException("A defuse key must carry exactly 32 bytes of key material.");
        return bytes;
    }

    public static bool TryValidateKeyAscii(string saved, out string error)
    {
        try
        {
            LoadKeyAscii(saved);
            error = "";
            return true;
        }
        catch (CipherException ex)
        {
            error = ex.Message;
            return false;
        }
    }

    // ------------------------------------------------- symmetric v2 core

    /// <summary>Encrypts with a raw 32-byte key and returns the hex string.</summary>
    public static string Encrypt(byte[] plaintext, byte[] rawKey) =>
        Primitives.Hex(EncryptRaw(plaintext, rawKey, null, null));

    /// <summary>Encrypts with a password (slow KDF inside) and returns hex.</summary>
    public static string EncryptWithPassword(byte[] plaintext, byte[] passwordUtf8) =>
        Primitives.Hex(EncryptPasswordRaw(plaintext, passwordUtf8, null, null));

    public static byte[] EncryptRaw(byte[] plaintext, byte[] rawKey, byte[]? salt, byte[]? iv)
    {
        if (rawKey.Length != KeySize)
            throw new CipherException("The defuse key must be 32 bytes.");
        salt ??= RandomNumberGenerator.GetBytes(SaltSize);
        iv ??= RandomNumberGenerator.GetBytes(BlockSize);

        var (authKey, encKey) = DeriveKeys(rawKey, salt);
        return Seal(plaintext, salt, iv, encKey, authKey);
    }

    public static byte[] EncryptPasswordRaw(byte[] plaintext, byte[] passwordUtf8, byte[]? salt, byte[]? iv)
    {
        salt ??= RandomNumberGenerator.GetBytes(SaltSize);
        iv ??= RandomNumberGenerator.GetBytes(BlockSize);

        var prehash = SHA256.HashData(passwordUtf8);
        var prekey = Primitives.Pbkdf2Sha256(prehash, salt, Pbkdf2Iterations, KeySize);
        var (authKey, encKey) = DeriveKeys(prekey, salt);
        return Seal(plaintext, salt, iv, encKey, authKey);
    }

    private static byte[] Seal(byte[] plaintext, byte[] salt, byte[] iv, byte[] encKey, byte[] authKey)
    {
        var body = new byte[HeaderVersionSize + SaltSize + BlockSize + plaintext.Length];
        CiphertextHeader.CopyTo(body, 0);
        salt.CopyTo(body, HeaderVersionSize);
        iv.CopyTo(body, HeaderVersionSize + SaltSize);
        var ct = Primitives.AesCtr(encKey, iv, plaintext);
        ct.CopyTo(body, HeaderVersionSize + SaltSize + BlockSize);

        using var hmac = new HMACSHA256(authKey);
        var mac = hmac.ComputeHash(body);

        var full = new byte[body.Length + MacSize];
        body.CopyTo(full, 0);
        mac.CopyTo(full, body.Length);
        return full;
    }

    public static byte[] DecryptHex(string hexCiphertext, byte[] rawKey)
    {
        var (body, mac) = OpenHex(hexCiphertext);
        var salt = body[HeaderVersionSize..(HeaderVersionSize + SaltSize)];
        var (authKey, encKey) = DeriveKeys(rawKey, salt);
        return Unseal(body, mac, salt, encKey, authKey);
    }

    public static byte[] DecryptPasswordHex(string hexCiphertext, byte[] passwordUtf8)
    {
        var (body, mac) = OpenHex(hexCiphertext);
        var salt = body[HeaderVersionSize..(HeaderVersionSize + SaltSize)];
        var prehash = SHA256.HashData(passwordUtf8);
        var prekey = Primitives.Pbkdf2Sha256(prehash, salt, Pbkdf2Iterations, KeySize);
        var (authKey, encKey) = DeriveKeys(prekey, salt);
        return Unseal(body, mac, salt, encKey, authKey);
    }

    private static (byte[] Body, byte[] Mac) OpenHex(string hexCiphertext)
    {
        byte[] raw;
        try
        {
            raw = Primitives.Unhex(hexCiphertext.Trim());
        }
        catch (CipherException)
        {
            throw new CipherException("This does not look like a defuse ciphertext (invalid hex).");
        }
        if (raw.Length < MinimumCiphertextSize)
            throw new CipherException("The ciphertext is too short to be a defuse v2 message.");
        if (!raw.AsSpan(0, HeaderVersionSize).SequenceEqual(CiphertextHeader))
            throw new CipherException("Bad version header. This string was not produced by defuse/php-encryption v2, or it is corrupted.");
        return (raw[..^MacSize], raw[^MacSize..]);
    }

    private static byte[] Unseal(byte[] body, byte[] mac, byte[] salt, byte[] encKey, byte[] authKey)
    {
        using var hmac = new HMACSHA256(authKey);
        var expected = hmac.ComputeHash(body);
        if (!CryptographicOperations.FixedTimeEquals(expected, mac))
            throw new CipherException("Integrity check failed. Either the key/password is wrong or the ciphertext was modified.");

        var iv = body[(HeaderVersionSize + SaltSize)..(HeaderVersionSize + SaltSize + BlockSize)];
        var ct = body[(HeaderVersionSize + SaltSize + BlockSize)..];
        return Primitives.AesCtr(encKey, iv, ct);
    }

    /// <summary>HKDF-SHA256 splitting a secret into the two v2 subkeys.</summary>
    public static (byte[] AuthKey, byte[] EncKey) DeriveKeys(byte[] ikm, byte[] salt) =>
        (Primitives.HkdfSha256(ikm, salt, AuthenticationInfo, KeySize),
         Primitives.HkdfSha256(ikm, salt, EncryptionInfo, KeySize));

    // ------------------------------------- password-protected key (v2)

    /// <summary>Wraps a fresh random key with a password, mirroring
    /// KeyProtectedByPassword::createRandomPasswordProtectedKey.</summary>
    public static string CreatePasswordProtectedKey(string password)
    {
        var innerKey = NewKey();
        return WrapProtected(innerKey, password);
    }

    public static string WrapProtected(byte[] innerKey, string password)
    {
        // The PHP library hashes the password first, as domain separation,
        // then hands the raw digest to encryptWithPassword.
        var passwordDigest = SHA256.HashData(Primitives.Utf8.GetBytes(password));
        var wrapped = EncryptPasswordRaw(SaveKeyAscii(innerKey).ToAsciiBytes(), passwordDigest, null, null);
        return Primitives.Hex(WrapChecksummed(ProtectedKeyHeader, wrapped));
    }

    /// <summary>Unlocks a password-protected key, returning the raw 32 bytes.</summary>
    public static byte[] UnlockProtectedKey(string saved, string password)
    {
        var wrapped = LoadChecksummed(ProtectedKeyHeader, saved, "password-protected key");
        var passwordDigest = SHA256.HashData(Primitives.Utf8.GetBytes(password));
        var innerAscii = Primitives.Utf8.GetString(DecryptPasswordHex(Primitives.Hex(wrapped), passwordDigest));
        return LoadKeyAscii(innerAscii);
    }

    // --------------------------------------------------------- legacy v1

    /// <summary>Decrypts ciphertext from version 1.x of the library:
    /// HMAC(32) || IV(16) || AES-128-CBC, keys split by HKDF with a zero salt.</summary>
    public static byte[] LegacyDecrypt(string hexCiphertext, byte[] keyBytes)
    {
        if (keyBytes.Length != 16)
            throw new CipherException("The legacy format uses a 16-byte key.");

        byte[] raw;
        try
        {
            raw = Primitives.Unhex(hexCiphertext.Trim());
        }
        catch (CipherException)
        {
            throw new CipherException("Legacy input is not valid hex.");
        }
        if (raw.Length <= 16 + 32)
            throw new CipherException("The legacy ciphertext is too short.");

        var mac = raw[..32];
        var message = raw[32..];

        var akey = Primitives.HkdfSha256(keyBytes, new byte[32], LegacyAuthenticationInfoBytes.ToAsciiString(), 16);
        using (var hmac = new HMACSHA256(akey))
        {
            if (!CryptographicOperations.FixedTimeEquals(hmac.ComputeHash(message), mac))
                throw new CipherException("Integrity check failed. Wrong key or modified ciphertext.");
        }

        var ekey = Primitives.HkdfSha256(keyBytes, new byte[32], LegacyEncryptionInfoBytes.ToAsciiString(), 16);
        var iv = message[..16];
        var ct = message[16..];

        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = ekey;
        aes.IV = iv;
        try
        {
            using var dec = aes.CreateDecryptor();
            return dec.TransformFinalBlock(ct, 0, ct.Length);
        }
        catch (CryptographicException)
        {
            throw new CipherException("Decryption failed. The ciphertext is not valid AES-128-CBC data.");
        }
    }

    // -------------------------------------------------------- checksums

    private static byte[] WrapChecksummed(byte[] header, byte[] payload)
    {
        var checkedBytes = new byte[header.Length + payload.Length];
        header.CopyTo(checkedBytes, 0);
        payload.CopyTo(checkedBytes, header.Length);
        var checksum = SHA256.HashData(checkedBytes);
        var full = new byte[checkedBytes.Length + checksum.Length];
        checkedBytes.CopyTo(full, 0);
        checksum.CopyTo(full, checkedBytes.Length);
        return full;
    }

    private static byte[] LoadChecksummed(byte[] expectedHeader, string saved, string what)
    {
        var text = saved.TrimEnd('\r', '\n', '\0', '\t', ' ');
        byte[] bytes;
        try
        {
            bytes = Primitives.Unhex(text);
        }
        catch (CipherException)
        {
            throw new CipherException($"This is not a valid defuse {what} string (invalid hex).");
        }
        if (bytes.Length < HeaderVersionSize + 32)
            throw new CipherException($"The defuse {what} string is shorter than expected.");
        if (!bytes.AsSpan(0, HeaderVersionSize).SequenceEqual(expectedHeader))
            throw new CipherException($"Invalid header. Expected a defuse {what} string.");
        var checkedBytes = bytes[..^32];
        var checksum = bytes[^32..];
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(checkedBytes), checksum))
            throw new CipherException("Checksum mismatch. The key string is corrupted.");
        return bytes[HeaderVersionSize..^32];
    }
}

internal static class ByteStringExtensions
{
    public static byte[] ToAsciiBytes(this string s) => System.Text.Encoding.ASCII.GetBytes(s);

    public static string ToAsciiString(this byte[] b) => System.Text.Encoding.ASCII.GetString(b);
}
