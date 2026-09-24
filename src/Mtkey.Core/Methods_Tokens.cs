using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Mtkey.Core;

public sealed class JwtMethod : CipherMethod
{
    public override string Id => "jwt";
    public override string Name => "JWT";
    public override string Blurb => "JSON Web Tokens: sign a payload, or crack one open and check its signature.";
    public override string Learn =>
        "A JWT is three base64url chunks joined by dots: header.payload.signature. The " +
        "header names the algorithm, the payload carries claims (sub, exp, iat, roles), and " +
        "the signature is an HMAC (HS256, shared secret) or an RSA signature (RS256, private " +
        "key signs, public key verifies). Two things people get wrong constantly: a JWT is " +
        "encoded, not encrypted, anyone can read the payload; and never trust alg from the " +
        "token itself when verifying, attackers edit it to 'none'. Decode here shows all " +
        "three parts and checks expiry claims for you.";
    public override string WikiUrl => "https://en.wikipedia.org/wiki/JSON_Web_Token";
    public override string Category => "Tokens";
    public override IReadOnlyList<string> Aliases => new[] { "json web token", "bearer" };

    private static readonly string[] Algs = { "HS256", "HS384", "HS512", "RS256", "RS384", "RS512" };

    public override IReadOnlyList<FieldSpec> Fields { get; } = new[]
    {
        new FieldSpec
        {
            Name = "alg",
            Label = "Algorithm",
            Kind = FieldKind.Dropdown,
            Options = Algs,
            Default = "HS256",
            Hint = "HS* = shared secret. RS* = RSA keys. Must match the key you provide.",
        },
        new FieldSpec
        {
            Name = "secret",
            Label = "HMAC secret",
            Secret = true,
            Placeholder = "your-256-bit-secret",
            Hint = "Only for HS256/384/512.",
            Generator = GeneratorKind.Base64UrlBytes,
            GeneratorSize = 32,
        },
        new FieldSpec
        {
            Name = "priv",
            Label = "RSA private key (PEM)",
            Kind = FieldKind.Multiline,
            Secret = true,
            Placeholder = "-----BEGIN PRIVATE KEY-----",
            Hint = "Signs RS* tokens.",
            Generator = GeneratorKind.RsaKeyPair,
        },
        new FieldSpec
        {
            Name = "pub",
            Label = "RSA public key (PEM)",
            Kind = FieldKind.Multiline,
            Placeholder = "-----BEGIN PUBLIC KEY-----",
            Hint = "Verifies RS* tokens.",
            Generator = GeneratorKind.RsaKeyPair,
        },
    };

    public override string EncodeLabel => "Sign";
    public override string DecodeLabel => "Decode & verify";

    public override IReadOnlyDictionary<string, string> Generate(
        string field, IReadOnlyDictionary<string, string> current)
    {
        if (field is not ("pub" or "priv"))
            return base.Generate(field, current);
        if (!int.TryParse(current.GetValueOrDefault("bits", "2048"), out var bits))
            bits = 2048;
        using var rsa = RSA.Create(bits);
        return new Dictionary<string, string>
        {
            ["pub"] = rsa.ExportSubjectPublicKeyInfoPem(),
            ["priv"] = rsa.ExportPkcs8PrivateKeyPem(),
        };
    }

    public override CipherResult Process(CipherRequest r)
    {
        if (r.Direction == CipherDirection.Encode)
            return Sign(r);

        var token = r.Input.Trim();
        var parts = token.Split('.');
        if (parts.Length < 2 || parts.Length > 3)
            throw new CipherException("A JWT looks like header.payload.signature, two dots.");

        var headerJson = PrettyJson(DecodeSegment(parts[0], "header"));
        var payloadJson = PrettyJson(DecodeSegment(parts[1], "payload"));

        string alg;
        try
        {
            using var doc = JsonDocument.Parse(DecodeSegment(parts[0], "header"));
            alg = doc.RootElement.TryGetProperty("alg", out var algEl) ? algEl.GetString() ?? "none" : "none";
        }
        catch (JsonException)
        {
            throw new CipherException("The header is not valid JSON.");
        }

        var sb = new StringBuilder();
        sb.AppendLine("Header:").AppendLine(headerJson).AppendLine();
        sb.AppendLine("Payload:").AppendLine(payloadJson);

        var notes = new List<string> { $"Token algorithm: {alg}" };

        if (parts.Length == 2 || parts[2].Length == 0)
        {
            notes.Add("This token is UNSIGNED (alg none / empty signature). Anyone could have written it.");
        }
        else if (alg == "none")
        {
            notes.Add("Header says 'none' but a signature is attached. That mismatch is suspicious.");
        }
        else
        {
            var verified = Verify(token, parts, alg, r);
            if (!verified)
            {
                notes.Add("Signature does NOT check out. The token was modified or the key is wrong.");
                return new CipherResult(sb.ToString().TrimEnd(),
                    Note: string.Join("  |  ", notes),
                    Warning: "Signature verification failed.");
            }
            notes.Add("Signature checks out against the key you provided.");
        }

        var claimNote = DescribeClaims(parts[1]);
        if (claimNote != null)
            notes.Add(claimNote);

        return new CipherResult(sb.ToString().TrimEnd(), Note: string.Join("  |  ", notes));
    }

    private CipherResult Sign(CipherRequest r)
    {
        var alg = r.Field("alg");
        if (!Algs.Contains(alg))
            throw new CipherException("Pick one of the listed algorithms.");

        var payload = r.Input.Trim();
        if (payload.Length > 0)
        {
            try
            {
                using var doc = JsonDocument.Parse(payload);
                if (doc.RootElement.ValueKind != JsonValueKind.Object)
                    throw new CipherException("The payload must be a JSON object, { ... }.");
            }
            catch (JsonException ex)
            {
                throw new CipherException($"The payload is not valid JSON: {ex.Message}");
            }
        }
        else
        {
            payload = "{}";
        }

        var header = $"{{\"alg\":\"{alg}\",\"typ\":\"JWT\"}}";
        var signingInput = Primitives.Base64Url(Primitives.Utf8.GetBytes(header))
            + "." + Primitives.Base64Url(Primitives.Utf8.GetBytes(payload));
        var sig = SignBytes(alg, Primitives.Utf8.GetBytes(r.Field("secret")),
            r.Field("priv"), Primitives.Utf8.GetBytes(signingInput));
        return new CipherResult(signingInput + "." + Primitives.Base64Url(sig),
            Note: $"Signed with {alg}. Remember: the payload is readable by anyone.");
    }

    private static byte[] SignBytes(string alg, byte[] secret, string privPem, byte[] signingInput)
    {
        if (alg.StartsWith("HS"))
        {
            if (secret.Length == 0)
                throw new CipherException("HS algorithms need the HMAC secret. The dice rolls a strong one.");
            return alg switch
            {
                "HS256" => new HMACSHA256(secret).ComputeHash(signingInput),
                "HS384" => new HMACSHA384(secret).ComputeHash(signingInput),
                "HS512" => new HMACSHA512(secret).ComputeHash(signingInput),
                _ => throw new CipherException("Unknown HMAC algorithm."),
            };
        }

        var priv = privPem.Trim();
        if (priv.Length == 0)
            throw new CipherException($"{alg} needs the RSA private key to sign. Dice generates a pair.");
        using var rsa = RsaMethod.ImportKey(priv, "private");
        var (hash, _) = RsParams(alg);
        return rsa.SignData(signingInput, hash, RSASignaturePadding.Pkcs1);
    }

    private bool Verify(string token, string[] parts, string alg, CipherRequest r)
    {
        var signingInput = Primitives.Utf8.GetBytes(parts[0] + "." + parts[1]);
        var sig = Primitives.Unbase64Url(parts[2]);

        if (alg.StartsWith("HS"))
        {
            var secret = Primitives.Utf8.GetBytes(r.Field("secret"));
            if (secret.Length == 0)
                throw new CipherException("Provide the HMAC secret to verify an HS* token.");
            var expected = alg switch
            {
                "HS256" => new HMACSHA256(secret).ComputeHash(signingInput),
                "HS384" => new HMACSHA384(secret).ComputeHash(signingInput),
                "HS512" => new HMACSHA512(secret).ComputeHash(signingInput),
                _ => throw new CipherException($"Cannot verify algorithm {alg}."),
            };
            return CryptographicOperations.FixedTimeEquals(expected, sig);
        }

        if (!alg.StartsWith("RS"))
            throw new CipherException($"Verifying {alg} tokens is not supported here.");

        var pub = r.Field("pub").Trim();
        RSA rsa;
        if (pub.Length > 0)
        {
            rsa = RsaMethod.ImportKey(pub, "public");
        }
        else
        {
            var priv = r.Field("priv").Trim();
            if (priv.Length == 0)
                throw new CipherException("Provide the RSA public key (or the private key) to verify.");
            rsa = RsaMethod.ImportKey(priv, "private");
        }
        using var _ = rsa;
        var (hash, _) = RsParams(alg);
        return rsa.VerifyData(signingInput, sig, hash, RSASignaturePadding.Pkcs1);
    }

    private static (HashAlgorithmName, int) RsParams(string alg) => alg switch
    {
        "RS384" => (HashAlgorithmName.SHA384, 384),
        "RS512" => (HashAlgorithmName.SHA512, 512),
        _ => (HashAlgorithmName.SHA256, 256),
    };

    private static string DecodeSegment(string segment, string what)
    {
        try
        {
            return Primitives.Utf8.GetString(Primitives.Unbase64Url(segment));
        }
        catch (CipherException ex)
        {
            throw new CipherException($"The {what} segment is not valid base64url. {ex.Message}");
        }
    }

    private static string? DescribeClaims(string payloadSegment)
    {
        try
        {
            using var doc = JsonDocument.Parse(DecodeSegment(payloadSegment, "payload"));
            var root = doc.RootElement;
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var notes = new List<string>();

            if (root.TryGetProperty("exp", out var expEl) && expEl.ValueKind == JsonValueKind.Number)
            {
                var exp = expEl.GetInt64();
                notes.Add(exp < now
                    ? $"Expired {(now - exp) / 60} minutes ago"
                    : $"Valid for another {(exp - now) / 60} minutes");
            }
            if (root.TryGetProperty("nbf", out var nbfEl) && nbfEl.ValueKind == JsonValueKind.Number)
            {
                var nbf = nbfEl.GetInt64();
                if (nbf > now)
                    notes.Add($"Not valid yet, starts in {(nbf - now) / 60} minutes");
            }
            if (root.TryGetProperty("iat", out var iatEl) && iatEl.ValueKind == JsonValueKind.Number)
            {
                var iat = iatEl.GetInt64();
                notes.Add($"Issued {(now - iat) / 60} minutes ago");
            }
            return notes.Count > 0 ? string.Join(", ", notes) : null;
        }
        catch (JsonException)
        {
            return "Payload claims could not be read (not JSON).";
        }
    }

    internal static string PrettyJson(string json)
    {
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { AllowTrailingCommas = true });
        using var ms = new MemoryStream();
        using (var writer = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
        {
            doc.WriteTo(writer);
        }
        return Primitives.Utf8.GetString(ms.ToArray());
    }
}

public sealed class JwksMethod : CipherMethod
{
    public override string Id => "jwks";
    public override string Name => "JWKS";
    public override string Blurb => "JSON Web Key Set: publish verification keys as JSON, or inspect one.";
    public override string Learn =>
        "A JWKS is the standard way services publish their public keys: {" +
        "\"keys\":[...]} where each JWK describes a key with fields like kty (key type), " +
        "kid (key id), n and e (an RSA modulus and exponent in base64url). Auth servers " +
        "expose a JWKS endpoint so anyone can verify their JWTs without shipping PEM files. " +
        "Encode mints a key set from your RSA key (or a fresh one). Decode inspects a JWKS " +
        "and hands you the PEM form of each RSA key it finds.";
    public override string WikiUrl => "https://en.wikipedia.org/wiki/JSON_Web_Key";
    public override string Category => "Tokens";
    public override IReadOnlyList<string> Aliases => new[] { "json web key", "jwk" };

    public override IReadOnlyList<FieldSpec> Fields { get; } = new[]
    {
        new FieldSpec
        {
            Name = "priv",
            Label = "RSA private key (PEM)",
            Kind = FieldKind.Multiline,
            Secret = true,
            Placeholder = "leave empty to mint a fresh 2048-bit key",
            Hint = "Empty + Encode = new keypair. The private parts go into the JWK.",
            Generator = GeneratorKind.RsaKeyPair,
        },
        new FieldSpec
        {
            Name = "kid",
            Label = "Key ID (kid)",
            Placeholder = "auto: 8 random hex chars",
            Hint = "Tokens reference the key they were signed with by this id.",
            Generator = GeneratorKind.TextSalt,
            GeneratorSize = 8,
        },
    };

    public override string EncodeLabel => "Build key set";
    public override string DecodeLabel => "Inspect";

    public override IReadOnlyDictionary<string, string> Generate(
        string field, IReadOnlyDictionary<string, string> current)
    {
        if (field is not ("pub" or "priv"))
            return base.Generate(field, current);
        if (!int.TryParse(current.GetValueOrDefault("bits", "2048"), out var bits))
            bits = 2048;
        using var rsa = RSA.Create(bits);
        return new Dictionary<string, string>
        {
            ["pub"] = rsa.ExportSubjectPublicKeyInfoPem(),
            ["priv"] = rsa.ExportPkcs8PrivateKeyPem(),
        };
    }

    public override CipherResult Process(CipherRequest r)
    {
        if (r.Direction == CipherDirection.Encode)
        {
            var privPem = r.Field("priv").Trim();
            RSA rsa;
            bool minted = false;
            if (privPem.Length > 0)
            {
                rsa = RsaMethod.ImportKey(privPem, "private");
            }
            else
            {
                rsa = RSA.Create(2048);
                minted = true;
            }
            using var _ = rsa;

            var kid = r.Field("kid").Trim();
            if (kid.Length == 0)
                kid = Primitives.RandomHex(4);

            var jwk = RsaToJwk(rsa, kid, includePrivate: true);
            var jwks = "{\"keys\":[" + jwk + "]}";
            return new CipherResult(JwtMethod.PrettyJson(jwks),
                Note: minted
                    ? $"Minted a fresh RSA-2048 key with kid '{kid}'."
                    : $"Built from your key, kid '{kid}'.");
        }

        return Inspect(r.Input);
    }

    private static CipherResult Inspect(string input)
    {
        JsonElement keysRoot;
        try
        {
            using var doc = JsonDocument.Parse(input.Trim(), new JsonDocumentOptions { AllowTrailingCommas = true });
            var root = doc.RootElement.Clone();
            keysRoot = root.ValueKind == JsonValueKind.Array ? root
                : root.TryGetProperty("keys", out var keys) ? keys.Clone()
                : throw new CipherException("This is neither a key set {\"keys\":[...]} nor an array of JWKs.");
        }
        catch (JsonException)
        {
            throw new CipherException("The input is not valid JSON.");
        }

        if (keysRoot.GetArrayLength() == 0)
            throw new CipherException("The key set contains no keys.");

        var sb = new StringBuilder();
        var index = 0;
        foreach (var key in keysRoot.EnumerateArray())
        {
            index++;
            var kty = key.TryGetProperty("kty", out var ktyEl) ? ktyEl.GetString() : "?";
            var kid = key.TryGetProperty("kid", out var kidEl) ? kidEl.GetString() : "";
            var use = key.TryGetProperty("use", out var useEl) ? useEl.GetString() : "";
            var alg = key.TryGetProperty("alg", out var algEl) ? algEl.GetString() : "";

            sb.AppendLine($"Key {index}: kty={kty}" +
                (kid?.Length > 0 ? $", kid={kid}" : "") +
                (use?.Length > 0 ? $", use={use}" : "") +
                (alg?.Length > 0 ? $", alg={alg}" : ""));

            if (kty == "RSA")
            {
                try
                {
                    using var rsa = RsaFromJwk(key);
                    var hasPrivate = key.TryGetProperty("d", out _);
                    sb.AppendLine($"  Size: {rsa.KeySize}-bit{(hasPrivate ? " (private material present)" : "")}");
                    sb.AppendLine("  Public PEM:");
                    sb.AppendLine(rsa.ExportSubjectPublicKeyInfoPem().TrimEnd());
                    if (hasPrivate)
                    {
                        sb.AppendLine("  Private PEM:");
                        sb.AppendLine(rsa.ExportPkcs8PrivateKeyPem().TrimEnd());
                    }
                }
                catch (CipherException ex)
                {
                    sb.AppendLine($"  Could not reconstruct the key: {ex.Message}");
                }
            }
            else if (kty == "EC" || kty == "OKP")
            {
                sb.AppendLine("  Elliptic-curve key: sizes and PEM export for EC/OKP are not supported here.");
            }
            sb.AppendLine();
        }
        return new CipherResult(sb.ToString().TrimEnd(),
            Note: $"{keysRoot.GetArrayLength()} key(s) found.");
    }

    internal static string RsaToJwk(RSA rsa, string kid, bool includePrivate)
    {
        var p = rsa.ExportParameters(includePrivate);
        var sb = new StringBuilder();
        sb.Append("{\"kty\":\"RSA\"");
        if (kid.Length > 0)
            sb.Append($",\"kid\":\"{kid}\"");
        sb.Append(",\"use\":\"sig\"");
        // RS256 is the usual pairing for verification keys; the hash choice is
        // independent of the key size, so we do not pretend otherwise.
        sb.Append(",\"alg\":\"RS256\"");
        sb.Append($",\"n\":\"{Primitives.Base64Url(p.Modulus!)}\"");
        sb.Append($",\"e\":\"{Primitives.Base64Url(p.Exponent!)}\"");
        if (includePrivate && p.D != null)
        {
            sb.Append($",\"d\":\"{Primitives.Base64Url(p.D)}\"");
            sb.Append($",\"p\":\"{Primitives.Base64Url(p.P!)}\"");
            sb.Append($",\"q\":\"{Primitives.Base64Url(p.Q!)}\"");
            sb.Append($",\"dp\":\"{Primitives.Base64Url(p.DP!)}\"");
            sb.Append($",\"dq\":\"{Primitives.Base64Url(p.DQ!)}\"");
            sb.Append($",\"qi\":\"{Primitives.Base64Url(p.InverseQ!)}\"");
        }
        sb.Append('}');
        return sb.ToString();
    }

    internal static RSA RsaFromJwk(JsonElement jwk)
    {
        byte[] N(string name)
        {
            if (!jwk.TryGetProperty(name, out var el))
                throw new CipherException($"Missing '{name}' in the JWK.");
            var bytes = Primitives.Unbase64Url(el.GetString() ?? "");
            return bytes.Length > 1 && bytes[0] == 0 ? bytes[1..] : bytes;
        }

        var parameters = new RSAParameters
        {
            Modulus = N("n"),
            Exponent = N("e"),
        };
        if (jwk.TryGetProperty("d", out _))
        {
            parameters.D = N("d");
            parameters.P = N("p");
            parameters.Q = N("q");
            parameters.DP = N("dp");
            parameters.DQ = N("dq");
            parameters.InverseQ = N("qi");
        }
        try
        {
            var rsa = RSA.Create();
            rsa.ImportParameters(parameters);
            return rsa;
        }
        catch (CryptographicException)
        {
            throw new CipherException("The JWK numbers do not form a valid RSA key.");
        }
    }
}

public static class TokenMethods
{
    public static IEnumerable<CipherMethod> All()
    {
        yield return new JwtMethod();
        yield return new JwksMethod();
    }
}
