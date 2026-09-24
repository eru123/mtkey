using Mtkey.Core;
using Xunit.Abstractions;

namespace Mtkey.Tests;

public class MtkeyTests
{
    private readonly ITestOutputHelper _output;

    public MtkeyTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void SelfTestPassesEveryCase()
    {
        var results = SelfTest.Run();
        foreach (var c in results.Where(c => !c.Pass))
            _output.WriteLine($"FAIL {c.Name}: {c.Detail}");
        Assert.All(results, c => Assert.True(c.Pass, $"{c.Name}: {c.Detail}"));
        Assert.True(results.Count >= 20, $"expected a healthy case count, got {results.Count}");
    }

    [Fact]
    public void EveryRegisteredMethodIsCallableAndSearchable()
    {
        Assert.True(Registry.All.Count >= 30, $"only {Registry.All.Count} methods registered");
        foreach (var method in Registry.All)
        {
            Assert.False(string.IsNullOrWhiteSpace(method.Name));
            Assert.False(string.IsNullOrWhiteSpace(method.WikiUrl));
            Assert.StartsWith("http", method.WikiUrl);
            Assert.Contains(method, Registry.Search(method.Name));
        }
    }

    [Fact]
    public void SearchFindsByAliasAndFilters()
    {
        Assert.Contains(Registry.All.First(m => m.Id == "base64"), Registry.Search("b64"));
        Assert.Contains(Registry.All.First(m => m.Id == "sha256"), Registry.Search("sha2"));
        Assert.Contains(Registry.All.First(m => m.Id == "defuse-encrypt"), Registry.Search("defuse"));
        Assert.Contains(Registry.All.First(m => m.Id == "jwt"), Registry.Search("json web"));
        Assert.Empty(Registry.Search("zzzznope"));
        Assert.Equal(Registry.All.Count, Registry.Search("").Count());
    }

    [Fact]
    public void OneWayMethodsHideDecode()
    {
        Assert.False(Registry.Find("md5")!.TwoWay);
        Assert.False(Registry.Find("pbkdf2")!.TwoWay);
        Assert.False(Registry.Find("defuse-legacy")!.TwoWay);
        Assert.True(Registry.Find("base64")!.TwoWay);
        Assert.True(Registry.Find("rsa")!.TwoWay);
    }

    [Fact]
    public void HashMethodsRejectEmptyRequiredFieldsPolitely()
    {
        Assert.Throws<CipherException>(() =>
            SelfTest.Run(new HmacMethod("x", "x", "", "", "", (_, _) => Array.Empty<byte>()),
                CipherDirection.Encode, "data"));
    }

    [Fact]
    public void FieldDefaultsAndDiceExistForRandomFields()
    {
        foreach (var method in Registry.All)
        foreach (var field in method.Fields)
        {
            if (field.Generator is null) continue;
            var values = method.Generate(field.Name,
                method.Fields.ToDictionary(f => f.Name, f => f.Default ?? ""));
            Assert.Contains(field.Name, values.Keys);
            Assert.True(values[field.Name].Length > 0, $"{method.Id}.{field.Name} generator returned nothing");
        }
    }

    [Fact]
    public void EncodingMethodsRoundtripTextWithEmoji()
    {
        var sample = "attack at dawn 🎲 café";
        foreach (var id in new[] { "base64", "base32", "base58", "hex", "binary", "url" })
        {
            var method = Registry.Find(id)!;
            var enc = method.Process(new CipherRequest(CipherDirection.Encode, sample, new Dictionary<string, string>()));
            var dec = method.Process(new CipherRequest(CipherDirection.Decode, enc.Output, new Dictionary<string, string>()));
            Assert.Equal(sample, dec.Output);
        }
    }

    [Fact]
    public void ClassicalCiphersRoundtrip()
    {
        var sample = "The Quick Brown Fox Jumps Over 12 Lazy Dogs!";
        foreach (var (id, fields) in new[]
        {
            ("caesar", new Dictionary<string, string> { ["shift"] = "17" }),
            ("vigenere", new Dictionary<string, string> { ["key"] = "LEMONPIE" }),
            ("railfence", new Dictionary<string, string> { ["rails"] = "4" }),
            ("xor", new Dictionary<string, string> { ["key"] = "secret" }),
        })
        {
            var method = Registry.Find(id)!;
            var enc = method.Process(new CipherRequest(CipherDirection.Encode, sample, fields));
            var dec = method.Process(new CipherRequest(CipherDirection.Decode, enc.Output, fields));
            Assert.Equal(sample, dec.Output);
        }

        // Playfair eats case, spacing and digits, and pads odd input with X,
        // so the roundtrip is compared on its terms: uppercase letters only.
        var playfair = Registry.Find("playfair")!;
        var pfFields = new Dictionary<string, string> { ["key"] = "MONARCHY" };
        var letters = new string(sample.Where(char.IsLetter).ToArray()).ToUpperInvariant();
        var pfEnc = playfair.Process(new CipherRequest(CipherDirection.Encode, sample, pfFields));
        var pfDec = playfair.Process(new CipherRequest(CipherDirection.Decode, pfEnc.Output, pfFields));
        // Playfair merges J into I, so both sides speak I.
        var normalized = letters.Replace('J', 'I');
        var expected = normalized.Length % 2 == 1 ? normalized + "X" : normalized;
        Assert.Equal(expected, pfDec.Output.Replace(" ", ""));
    }

    [Fact]
    public void DefuseKeyValidationCatchesCorruption()
    {
        var key = DefuseCrypto.NewKeyAscii();
        Assert.True(DefuseCrypto.TryValidateKeyAscii(key, out _));

        var last = key[^1];
        var corrupted = key[..^1] + (last == '0' ? '1' : '0');
        Assert.False(DefuseCrypto.TryValidateKeyAscii(corrupted, out var error));
        Assert.Contains("Checksum", error);
    }

    [Fact]
    public void DefuseCiphertextFromPhpLoadsHere()
    {
        var vectors = System.Text.Json.JsonDocument.Parse(
            File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "vectors.json"))).RootElement;

        var keyVector = vectors.GetProperty("v2_key");
        var method = (DefuseKeyMethod)Registry.Find("defuse-encrypt")!;
        var result = method.Process(new CipherRequest(
            CipherDirection.Decode,
            keyVector.GetProperty("ciphertext_hex").GetString()!,
            new Dictionary<string, string> { ["key"] = keyVector.GetProperty("key_ascii").GetString()! }));

        Assert.Equal(keyVector.GetProperty("plaintext").GetString(), result.Output);
    }
}
