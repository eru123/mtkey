using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Mtkey.Core;

/// <summary>Low-level helpers shared by the cipher methods. Everything here is
/// deterministic except the Random* generators.</summary>
public static class Primitives
{
    public static readonly Encoding Utf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    // ---------------------------------------------------------------- hex

    public static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    public static byte[] Unhex(string text)
    {
        var cleaned = text.Replace(" ", "").Replace("\r", "").Replace("\n", "").Replace("\t", "");
        if (cleaned.Length == 0 || cleaned.Length % 2 != 0)
            throw new CipherException("Hex input must have an even number of digits.");
        try
        {
            return Convert.FromHexString(cleaned);
        }
        catch (FormatException)
        {
            throw new CipherException("Hex input contains characters other than 0-9 and a-f.");
        }
    }

    // ------------------------------------------------------------ base64

    public static string Base64(byte[] bytes) => Convert.ToBase64String(bytes);

    public static byte[] Unbase64(string text)
    {
        var cleaned = text.Replace("\r", "").Replace("\n", "").Replace(" ", "").TrimEnd('=');
        var pad = (cleaned.Length % 4) switch
        {
            2 => "==",
            3 => "=",
            0 => "",
            _ => throw new CipherException("Base64 input has an invalid length."),
        };
        try
        {
            return Convert.FromBase64String(cleaned + pad);
        }
        catch (FormatException)
        {
            throw new CipherException("Base64 input contains invalid characters.");
        }
    }

    public static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] Unbase64Url(string text)
    {
        var cleaned = text.Replace("\r", "").Replace("\n", "").Replace(" ", "");
        var b64 = cleaned.Replace('-', '+').Replace('_', '/');
        var pad = (b64.Length % 4) switch
        {
            2 => "==",
            3 => "=",
            0 => "",
            _ => throw new CipherException("Base64url input has an invalid length."),
        };
        try
        {
            return Convert.FromBase64String(b64 + pad);
        }
        catch (FormatException)
        {
            throw new CipherException("Base64url input contains invalid characters.");
        }
    }

    // ------------------------------------------------------------ base32

    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Base32(byte[] bytes)
    {
        var sb = new StringBuilder();
        int buffer = 0, bits = 0;
        foreach (var b in bytes)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                sb.Append(Base32Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0)
            sb.Append(Base32Alphabet[(buffer << (5 - bits)) & 31]);
        return sb.ToString();
    }

    public static byte[] Unbase32(string text)
    {
        var cleaned = text.Replace("=", "").Replace(" ", "").Replace("\r", "").Replace("\n", "").ToUpperInvariant();
        if (cleaned.Length == 0)
            throw new CipherException("Base32 input is empty.");
        var bytes = new List<byte>();
        int buffer = 0, bits = 0;
        foreach (var c in cleaned)
        {
            var v = Base32Alphabet.IndexOf(c);
            if (v < 0)
                throw new CipherException($"Base32 input contains the invalid character '{c}'.");
            buffer = (buffer << 5) | v;
            bits += 5;
            if (bits >= 8)
            {
                bytes.Add((byte)((buffer >> (bits - 8)) & 0xFF));
                bits -= 8;
            }
        }
        return bytes.ToArray();
    }

    // ------------------------------------------------------------ base58

    private const string Base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    public static string Base58(byte[] bytes)
    {
        var leadingZeros = 0;
        while (leadingZeros < bytes.Length && bytes[leadingZeros] == 0)
            leadingZeros++;

        if (bytes.Length == 0)
            return "";

        var b58 = new byte[bytes.Length * 2];
        int length = 0;
        for (var i = leadingZeros; i < bytes.Length; i++)
        {
            int carry = bytes[i];
            for (var j = 0; j < length; j++)
            {
                carry += 256 * b58[j];
                b58[j] = (byte)(carry % 58);
                carry /= 58;
            }
            while (carry > 0)
            {
                b58[length++] = (byte)(carry % 58);
                carry /= 58;
            }
        }

        var sb = new StringBuilder(leadingZeros + length);
        sb.Append('1', leadingZeros);
        for (var i = length - 1; i >= 0; i--)
            sb.Append(Base58Alphabet[b58[i]]);
        return sb.ToString();
    }

    public static byte[] Unbase58(string text)
    {
        var cleaned = text.Replace(" ", "").Replace("\r", "").Replace("\n", "");
        if (cleaned.Length == 0)
            throw new CipherException("Base58 input is empty.");

        var leadingOnes = 0;
        while (leadingOnes < cleaned.Length && cleaned[leadingOnes] == '1')
            leadingOnes++;

        var bytes = new List<byte>();
        foreach (var c in cleaned)
        {
            var carry = Base58Alphabet.IndexOf(c);
            if (carry < 0)
                throw new CipherException($"Base58 input contains the invalid character '{c}'.");
            for (var j = 0; j < bytes.Count; j++)
            {
                carry += bytes[j] * 58;
                bytes[j] = (byte)(carry & 0xFF);
                carry >>= 8;
            }
            while (carry > 0)
            {
                bytes.Add((byte)(carry & 0xFF));
                carry >>= 8;
            }
        }

        var result = new byte[leadingOnes + bytes.Count];
        for (var i = 0; i < bytes.Count; i++)
            result[leadingOnes + i] = bytes[bytes.Count - 1 - i];
        return result;
    }

    // ------------------------------------------------------------- crc32

    private static readonly uint[] Crc32Table = BuildCrc32Table();

    private static uint[] BuildCrc32Table()
    {
        var table = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            var c = i;
            for (var k = 0; k < 8; k++)
                c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        return table;
    }

    public static uint Crc32(byte[] bytes)
    {
        uint crc = 0xFFFFFFFFu;
        foreach (var b in bytes)
            crc = Crc32Table[(crc ^ b) & 0xFF] ^ (crc >> 8);
        return crc ^ 0xFFFFFFFFu;
    }

    // -------------------------------------------------------------- kdf

    /// <summary>HKDF per RFC 5869 with HMAC-SHA256.</summary>
    public static byte[] HkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length)
    {
        byte[] prk;
        using (var hmac = new HMACSHA256(salt.Length == 0 ? new byte[32] : salt))
        {
            prk = hmac.ComputeHash(ikm);
        }

        var okm = new byte[length];
        var t = Array.Empty<byte>();
        var generated = 0;
        byte counter = 1;
        using (var hmac = new HMACSHA256(prk))
        {
            while (generated < length)
            {
                var input = new byte[t.Length + info.Length + 1];
                t.CopyTo(input, 0);
                info.CopyTo(input, t.Length);
                input[^1] = counter;
                t = hmac.ComputeHash(input);
                var take = Math.Min(t.Length, length - generated);
                Array.Copy(t, 0, okm, generated, take);
                generated += take;
                counter++;
            }
        }
        return okm;
    }

    /// <summary>PBKDF2-HMAC-SHA256.</summary>
    public static byte[] Pbkdf2Sha256(byte[] password, byte[] salt, int iterations, int length)
    {
        using var db = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
        return db.GetBytes(length);
    }

    public static byte[] HkdfSha256(byte[] ikm, byte[] salt, string asciiInfo, int length) =>
        HkdfSha256(ikm, salt, Encoding.ASCII.GetBytes(asciiInfo), length);

    public static byte[] Sha256(byte[] bytes) => SHA256.HashData(bytes);

    // ------------------------------------------------- aes ctr (openssl)

    /// <summary>AES-CTR with the whole 16-byte IV as a big-endian counter,
    /// the same way OpenSSL's aes-*-ctr treats it.</summary>
    public static byte[] AesCtr(byte[] key, byte[] iv16, byte[] data)
    {
        if (iv16.Length != 16)
            throw new CipherException("CTR mode needs a 16-byte IV.");
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = key;
        aes.IV = new byte[16]; // ECB ignores it, the API just wants one
        using var enc = aes.CreateEncryptor();

        var counter = (byte[])iv16;
        var keystream = new byte[16];
        var output = new byte[data.Length];
        for (var off = 0; off < data.Length; off += 16)
        {
            enc.TransformBlock(counter, 0, 16, keystream, 0);
            var n = Math.Min(16, data.Length - off);
            for (var i = 0; i < n; i++)
                output[off + i] = (byte)(data[off + i] ^ keystream[i]);
            IncrementBigEndian(counter);
        }
        return output;
    }

    private static void IncrementBigEndian(byte[] counter)
    {
        for (var i = counter.Length - 1; i >= 0; i--)
        {
            if (++counter[i] != 0)
                break;
        }
    }

    // ----------------------------------------------------------- random

    public static string RandomHex(int bytes) =>
        Convert.ToHexString(RandomNumberGenerator.GetBytes(bytes)).ToLowerInvariant();

    public static string RandomBase64(int bytes) =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(bytes));

    public static string RandomBase64Url(int bytes) =>
        Base64Url(RandomNumberGenerator.GetBytes(bytes));

    private const string PasswordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    private const string PasswordSymbols = "!@#$%^&*()-_=+?";

    /// <summary>Readable but strong password: length 20-ish with digits, symbols
    /// and mixed case guaranteed.</summary>
    public static string RandomPassword(int length = 20)
    {
        length = Math.Max(12, length);
        var chars = new char[length];
        for (var i = 0; i < length - 4; i++)
            chars[i] = PasswordAlphabet[RandomNumberGenerator.GetInt32(PasswordAlphabet.Length)];
        chars[^4] = PasswordSymbols[RandomNumberGenerator.GetInt32(PasswordSymbols.Length)];
        chars[^3] = (char)('2' + RandomNumberGenerator.GetInt32(8));
        chars[^2] = (char)('A' + RandomNumberGenerator.GetInt32(26));
        chars[^1] = (char)('a' + RandomNumberGenerator.GetInt32(26));
        return new string(chars.OrderBy(_ => RandomNumberGenerator.GetInt32(int.MaxValue)).ToArray());
    }

    /// <summary>Alphanumeric token, nice for salts that humans copy around.</summary>
    public static string RandomToken(int length = 16)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        var chars = new char[length];
        for (var i = 0; i < length; i++)
            chars[i] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
        return new string(chars);
    }

    // ----------------------------------------------------------- binary

    public static string ToBinary(byte[] bytes) =>
        string.Join(" ", bytes.Select(b => Convert.ToString(b, 2).PadLeft(8, '0')));

    public static byte[] FromBinary(string text)
    {
        var cleaned = text.Replace(" ", "").Replace("\r", "").Replace("\n", "");
        if (cleaned.Length == 0 || cleaned.Length % 8 != 0)
            throw new CipherException("Binary input must be groups of 8 bits.");
        var bytes = new byte[cleaned.Length / 8];
        for (var i = 0; i < bytes.Length; i++)
        {
            var chunk = cleaned.Substring(i * 8, 8);
            if (chunk.Any(c => c != '0' && c != '1'))
                throw new CipherException("Binary input contains characters other than 0 and 1.");
            bytes[i] = Convert.ToByte(chunk, 2);
        }
        return bytes;
    }

    // ------------------------------------------------------------- keys

    /// <summary>Decode key material that the user chose to enter as hex, base64
    /// or plain text.</summary>
    public static byte[] DecodeKeyMaterial(string value, string encoding)
    {
        var trimmed = value.Trim();
        return encoding switch
        {
            "Hex" => Unhex(trimmed),
            "Base64" => Unbase64(trimmed),
            "Text (UTF-8)" => Utf8.GetBytes(trimmed),
            _ => throw new CipherException($"Unknown key encoding {encoding}."),
        };
    }

    public static bool LooksLikeHex(string value)
    {
        var t = value.Replace(" ", "");
        return t.Length > 0 && t.Length % 2 == 0 && t.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');
    }
}
