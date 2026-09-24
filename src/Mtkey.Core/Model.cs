namespace Mtkey.Core;

using System.Security.Cryptography;

public enum CipherDirection
{
    Encode,
    Decode
}

public enum FieldKind
{
    Text,
    Multiline,
    Dropdown,
    Number
}

/// <summary>What the dice button next to a field should produce.</summary>
public enum GeneratorKind
{
    HexBytes,
    Base64Bytes,
    Base64UrlBytes,
    Password,
    TextSalt,
    Number,
    DefuseKey,
    RsaKeyPair,
}

public sealed record FieldSpec
{
    public required string Name { get; init; }
    public required string Label { get; init; }
    public FieldKind Kind { get; init; } = FieldKind.Text;
    public string? Placeholder { get; init; }
    public string[]? Options { get; init; }
    public string? Default { get; init; }
    public int? Min { get; init; }
    public int? Max { get; init; }

    /// <summary>Field content is a secret, so the UI masks it.</summary>
    public bool Secret { get; init; }

    /// <summary>Small grey hint shown under the label.</summary>
    public string? Hint { get; init; }

    public GeneratorKind? Generator { get; init; }

    /// <summary>Byte count for the byte-based generators.</summary>
    public int GeneratorSize { get; init; } = 32;

    /// <summary>Inclusive range for the Number generator.</summary>
    public (int Min, int Max)? GeneratorRange { get; init; }
}

public sealed record CipherRequest(
    CipherDirection Direction,
    string Input,
    IReadOnlyDictionary<string, string> Fields)
{
    public string Field(string name) =>
        Fields.TryGetValue(name, out var v) ? v : "";
}

public sealed record CipherResult(
    string Output,
    string? Note = null,
    string? Warning = null);

public sealed class CipherException : Exception
{
    public CipherException(string message) : base(message) { }
}

public sealed record FieldValidation(IReadOnlyDictionary<string, Validation> Fields, string Overall)
{
    public static readonly FieldValidation Empty = new(
        new Dictionary<string, Validation>(), "");
}

public sealed record Validation(bool Ok, string Message, bool Certain = false)
{
    public static Validation Unknown => new(true, "", Certain: false);
    public static Validation Good(string message) => new(true, message, Certain: true);
    public static Validation Bad(string message) => new(false, message, Certain: true);
}

public abstract class CipherMethod
{
    public abstract string Id { get; }
    public abstract string Name { get; }
    public abstract string Category { get; }

    /// <summary>One-liner shown under the selector.</summary>
    public abstract string Blurb { get; }

    /// <summary>Longer classroom-style explanation shown in the info area.</summary>
    public virtual string Learn => Blurb;

    public abstract string WikiUrl { get; }

    /// <summary>False for one-way functions, then only Encode is offered.</summary>
    public virtual bool TwoWay => true;

    public virtual string EncodeLabel => "Encode";
    public virtual string DecodeLabel => "Decode";

    /// <summary>Extra search terms so "b64" finds Base64 and "sha2" finds SHA-256.</summary>
    public virtual IReadOnlyList<string> Aliases => Array.Empty<string>();

    public virtual IReadOnlyList<FieldSpec> Fields => Array.Empty<FieldSpec>();

    public abstract CipherResult Process(CipherRequest request);

    /// <summary>Live validation of key material and other fields as the user types.</summary>
    public virtual FieldValidation ValidateFields(IReadOnlyDictionary<string, string> values) =>
        FieldValidation.Empty;

    /// <summary>Values produced by the dice button. May fill several fields at once
    /// (an RSA key pair, for example, is born together).</summary>
    public virtual IReadOnlyDictionary<string, string> Generate(
        string field,
        IReadOnlyDictionary<string, string> current)
    {
        var spec = Fields.FirstOrDefault(f => f.Name == field)
            ?? throw new CipherException($"No generator for {field}.");
        var value = spec.Generator switch
        {
            GeneratorKind.HexBytes => Primitives.RandomHex(spec.GeneratorSize),
            GeneratorKind.Base64Bytes => Primitives.RandomBase64(spec.GeneratorSize),
            GeneratorKind.Base64UrlBytes => Primitives.RandomBase64Url(spec.GeneratorSize),
            GeneratorKind.Password => Primitives.RandomPassword(spec.GeneratorSize),
            GeneratorKind.TextSalt => Primitives.RandomToken(spec.GeneratorSize),
            GeneratorKind.Number => RandomNumberGenerator.GetInt32(
                spec.GeneratorRange?.Min ?? 1,
                (spec.GeneratorRange?.Max ?? 10) + 1).ToString(),
            GeneratorKind.DefuseKey => DefuseCrypto.NewKeyAscii(),
            _ => throw new CipherException($"No generator for {field}."),
        };
        return new Dictionary<string, string> { [field] = value };
    }

    public override string ToString() => $"{Name} ({Category})";
}
