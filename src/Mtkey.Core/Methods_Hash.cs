using System.Security.Cryptography;
using System.Text;

namespace Mtkey.Core;

public abstract class HashMethodBase : CipherMethod
{
    public override string Category => "Hash";
    public override bool TwoWay => false;
    public override string EncodeLabel => "Hash";
    public override string DecodeLabel => "n/a";

    public override IReadOnlyList<FieldSpec> Fields { get; } = new[]
    {
        new FieldSpec
        {
            Name = "out",
            Label = "Output",
            Kind = FieldKind.Dropdown,
            Options = new[] { "Hex", "Base64" },
            Default = "Hex",
        },
    };

    protected static string Render(byte[] digest, string encoding) =>
        encoding == "Base64" ? Primitives.Base64(digest) : Primitives.Hex(digest);
}

public sealed class HashMethod : HashMethodBase
{
    private readonly string id, name, blurb, learn, wiki;
    private readonly Func<byte[], byte[]> hash;
    private readonly string[] aliases;

    public HashMethod(string id, string name, string blurb, string learn, string wiki,
        Func<byte[], byte[]> hash, string[]? aliases = null)
    {
        this.id = id; this.name = name; this.blurb = blurb;
        this.learn = learn; this.wiki = wiki; this.hash = hash;
        this.aliases = aliases ?? Array.Empty<string>();
    }

    public override string Id => id;
    public override string Name => name;
    public override string Blurb => blurb;
    public override string Learn => learn;
    public override string WikiUrl => wiki;
    public override IReadOnlyList<string> Aliases => aliases;

    public override CipherResult Process(CipherRequest r)
    {
        var outEnc = r.Field("out");
        var digest = hash(Primitives.Utf8.GetBytes(r.Input));
        return new CipherResult(Render(digest, outEnc));
    }
}

public sealed class HmacMethod : HashMethodBase
{
    private readonly string id, name, blurb, learn, wiki;
    private readonly Func<byte[], byte[], byte[]> mac;

    public HmacMethod(string id, string name, string blurb, string learn, string wiki,
        Func<byte[], byte[], byte[]> mac)
    {
        this.id = id; this.name = name; this.blurb = blurb;
        this.learn = learn; this.wiki = wiki; this.mac = mac;
    }

    public override string Id => id;
    public override string Name => name;
    public override string Blurb => blurb;
    public override string Learn => learn;
    public override string WikiUrl => wiki;

    public override IReadOnlyList<FieldSpec> Fields { get; } = new[]
    {
        new FieldSpec
        {
            Name = "key",
            Label = "Secret key",
            Secret = true,
            Placeholder = "correct horse battery staple",
            Hint = "Only someone with this exact key can produce the same digest.",
            Generator = GeneratorKind.Password,
            GeneratorSize = 24,
        },
        new FieldSpec
        {
            Name = "out",
            Label = "Output",
            Kind = FieldKind.Dropdown,
            Options = new[] { "Hex", "Base64" },
            Default = "Hex",
        },
    };

    public override CipherResult Process(CipherRequest r)
    {
        var key = Primitives.Utf8.GetBytes(r.Field("key"));
        if (key.Length == 0)
            throw new CipherException("HMAC needs a secret key.");
        var digest = mac(key, Primitives.Utf8.GetBytes(r.Input));
        return new CipherResult(Render(digest, r.Field("out")));
    }
}

public sealed class Crc32Method : HashMethodBase
{
    public override string Id => "crc32";
    public override string Name => "CRC-32";
    public override string Blurb => "A checksum for spotting corruption, not a cryptographic hash.";
    public override string Learn =>
        "CRC-32 produces a 32-bit check value that changes when data changes. It catches " +
        "accidental corruption (network noise, disk errors) but is trivial to fake on " +
        "purpose, so it protects against accidents, never against attackers. ZIP files, " +
        "Ethernet frames and PNG images carry one.";
    public override string WikiUrl => "https://en.wikipedia.org/wiki/CRC-32";

    public override CipherResult Process(CipherRequest r)
    {
        var crc = Primitives.Crc32(Primitives.Utf8.GetBytes(r.Input));
        var hex = crc.ToString("x8");
        return new CipherResult(r.Field("out") == "Base64"
            ? Primitives.Base64(new[] { (byte)(crc >> 24), (byte)(crc >> 16), (byte)(crc >> 8), (byte)crc })
            : hex,
            Note: $"0x{hex.ToUpperInvariant()}");
    }
}

public sealed class Pbkdf2Method : HashMethodBase
{
    public override string Id => "pbkdf2";
    public override string Name => "PBKDF2";
    public override string Blurb => "Stretches a password into a key by hashing it thousands of times.";
    public override string Learn =>
        "Passwords make weak keys because humans pick guessable ones. PBKDF2 repeats " +
        "HMAC-SHA256 tens or hundreds of thousands of times so that each password guess " +
        "costs an attacker real computing time. The salt makes precomputed password tables " +
        "useless. WPA2 WiFi, KeePass and many password vaults use PBKDF2; the defuse " +
        "password mode below uses 100,000 rounds, a number that keeps rising as computers " +
        "get faster.";
    public override string WikiUrl => "https://en.wikipedia.org/wiki/PBKDF2";
    public override IReadOnlyList<string> Aliases => new[] { "kdf" };

    public override IReadOnlyList<FieldSpec> Fields { get; } = new[]
    {
        new FieldSpec
        {
            Name = "password",
            Label = "Password",
            Secret = true,
            Placeholder = "hunter2",
            Generator = GeneratorKind.Password,
        },
        new FieldSpec
        {
            Name = "salt",
            Label = "Salt",
            Placeholder = "sea salt, kosher salt, any random text",
            Hint = "Random per user. Stored next to the hash, never secret itself.",
            Generator = GeneratorKind.TextSalt,
            GeneratorSize = 16,
        },
        new FieldSpec
        {
            Name = "iterations",
            Label = "Iterations",
            Kind = FieldKind.Number,
            Default = "100000",
            Min = 1,
            Max = 10_000_000,
            Hint = "Higher is safer and slower. 100k is the defuse library's choice.",
        },
        new FieldSpec
        {
            Name = "out",
            Label = "Output",
            Kind = FieldKind.Dropdown,
            Options = new[] { "Hex", "Base64" },
            Default = "Hex",
        },
    };

    public override CipherResult Process(CipherRequest r)
    {
        if (!int.TryParse(r.Field("iterations").Trim(), out var iters) || iters < 1 || iters > 10_000_000)
            throw new CipherException("Iterations must be between 1 and 10,000,000.");
        var salt = Primitives.Utf8.GetBytes(r.Field("salt"));
        if (salt.Length == 0)
            throw new CipherException("PBKDF2 needs a salt. The dice button will invent one.");
        var key = Primitives.Pbkdf2Sha256(
            Primitives.Utf8.GetBytes(r.Field("password")), salt, iters, 32);
        return new CipherResult(Render(key, r.Field("out")),
            Note: $"PBKDF2-HMAC-SHA256, {iters:N0} iterations, 32-byte key");
    }
}

public static class HashMethods
{
    public static IEnumerable<CipherMethod> All()
    {
        yield return new HashMethod("md5", "MD5", "128-bit hash from 1991, broken for signatures since 2004.",
            "MD5 was everywhere: file checksums, password storage, certificate signatures. " +
            "Researchers then found ways to craft two different inputs with the same MD5, and " +
            "real certificates were forged with the trick in 2008. It still works fine as a " +
            "fingerprint for accidental corruption, but never trust it against an attacker.",
            "https://en.wikipedia.org/wiki/MD5", MD5.HashData, new[] { "digest" });

        yield return new HashMethod("sha1", "SHA-1", "160-bit hash, officially retired in 2017.",
            "SHA-1 was the standard hash for two decades. Google and CWI Amsterdam pulled off " +
            "the first practical collision in 2017 (two different PDFs, same SHA-1) at a cost " +
            "of about 110 GPU-years. Browsers dropped it the same year. Interesting fact: " +
            "Git still uses SHA-1 internally, with extra checks layered on top.",
            "https://en.wikipedia.org/wiki/SHA-1", SHA1.HashData, new[] { "digest" });

        yield return new HashMethod("sha256", "SHA-256", "The workhorse of modern hashing.",
            "SHA-256 belongs to the SHA-2 family designed by the NSA and published in 2001. " +
            "It guards TLS certificates, Bitcoin proof-of-work, package signatures and JWT " +
            "signing (the RS256 and HS256 you see in tokens are SHA-256 inside). No practical " +
            "attack is known against it.",
            "https://en.wikipedia.org/wiki/SHA-2", SHA256.HashData, new[] { "sha2", "sha-256", "digest" });

        yield return new HashMethod("sha384", "SHA-384", "SHA-2 with a 384-bit digest.",
            "SHA-384 is SHA-512 with two thirds of the output and different starting values. " +
            "You meet it in TLS cipher suites and in JWT's RS384/HS384 algorithms where a " +
            "192-bit security level is wanted.",
            "https://en.wikipedia.org/wiki/SHA-2", SHA384.HashData, new[] { "sha2", "digest" });

        yield return new HashMethod("sha512", "SHA-512", "SHA-2 with the full 512-bit digest.",
            "SHA-512 processes data in 64-bit words, which makes it fast on 64-bit CPUs, " +
            "sometimes faster than SHA-256. Password hashes based on raw SHA-512 are a bad " +
            "idea though, it is too quick; that is what PBKDF2 and friends are for.",
            "https://en.wikipedia.org/wiki/SHA-2", SHA512.HashData, new[] { "sha2", "digest" });

        if (SHA3_256.IsSupported)
            yield return new HashMethod("sha3-256", "SHA-3 (256)", "The newest NIST hash standard, a totally different design.",
                "SHA-3 came from the Keccak sponge construction, chosen by NIST in 2012 after " +
                "cryptographers worried SHA-2 might fall the way SHA-1 did. It squeezes output " +
                "from a soaked sponge state rather than compressing blocks, so it is built on " +
                "entirely different mathematics than the SHA-1/SHA-2 family.",
                "https://en.wikipedia.org/wiki/SHA-3", SHA3_256.HashData, new[] { "keccak", "digest" });

        yield return new HmacMethod("hmac-md5", "HMAC-MD5", "MAC built on MD5. Educational only.",
            "HMAC wraps a hash with a secret key so only key holders can reproduce the tag. " +
            "Even though plain MD5 is collision-broken, HMAC-MD5 has no practical break, but " +
            "nobody should pick it in 2026 when HMAC-SHA256 costs the same.",
            "https://en.wikipedia.org/wiki/HMAC",
            (key, data) => new HMACMD5(key).ComputeHash(data));

        yield return new HmacMethod("hmac-sha1", "HMAC-SHA1", "Keyed hash on SHA-1.",
            "HMAC-SHA1 still appears in older APIs and AWS Signature V3-era tooling. " +
            "It works, but every new system should reach for a SHA-2 based MAC.",
            "https://en.wikipedia.org/wiki/HMAC",
            (key, data) => new HMACSHA1(key).ComputeHash(data));

        yield return new HmacMethod("hmac-sha256", "HMAC-SHA256", "Keyed hash on SHA-256. The default MAC.",
            "HMAC-SHA256 is the integrity half of TLS records, the JWT HS256 algorithm, " +
            "AWS Signature V4, TOTP authenticator codes and the defuse library's " +
            "authentication layer. Knowing the hash reveals nothing; the key is what " +
            "makes the tag unforgeable.",
            "https://en.wikipedia.org/wiki/HMAC",
            (key, data) => new HMACSHA256(key).ComputeHash(data));

        yield return new HmacMethod("hmac-sha512", "HMAC-SHA512", "Keyed hash on SHA-512.",
            "The long version of HMAC-SHA256, used where a 256-bit tag is wanted, for " +
            "example in JWT HS512 and some blockchain signing schemes.",
            "https://en.wikipedia.org/wiki/HMAC",
            (key, data) => new HMACSHA512(key).ComputeHash(data));

        yield return new Crc32Method();
        yield return new Pbkdf2Method();
    }
}
