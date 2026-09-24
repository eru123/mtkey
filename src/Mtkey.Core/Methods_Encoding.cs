using System.Text;

namespace Mtkey.Core;

public abstract class EncodingMethod : CipherMethod
{
    public override string Category => "Encoding";

    protected static byte[] InputBytes(CipherRequest r) => Primitives.Utf8.GetBytes(r.Input);
}

public sealed class Base64Method : EncodingMethod
{
    public override string Id => "base64";
    public override string Name => "Base64";
    public override string Blurb => "Wraps binary data in 64 safe alphabet characters.";
    public override string Learn =>
        "Base64 turns any bytes into letters, digits, + and / so they can travel through " +
        "systems that only understand text (email, JSON, URLs). Every 3 bytes become 4 " +
        "characters, which is why encoded data is about a third bigger. It hides nothing: " +
        "anyone can reverse it, it is an encoding, not encryption.";
    public override string WikiUrl => "https://en.wikipedia.org/wiki/Base64";
    public override IReadOnlyList<string> Aliases => new[] { "b64" };

    public override CipherResult Process(CipherRequest r) => r.Direction == CipherDirection.Encode
        ? new CipherResult(Primitives.Base64(InputBytes(r)))
        : new CipherResult(Primitives.Utf8.GetString(Primitives.Unbase64(r.Input)));
}

public sealed class Base32Method : EncodingMethod
{
    public override string Id => "base32";
    public override string Name => "Base32";
    public override string Blurb => "Same idea as Base64 but case-insensitive, A-Z and 2-7.";
    public override string Learn =>
        "Base32 uses 32 characters, all upper-case letters and the digits 2 to 7, so it " +
        "survives being read out loud, printed without case, or punched into a hardware " +
        "token. TOTP authenticator secrets are usually Base32 for exactly this reason.";
    public override string WikiUrl => "https://en.wikipedia.org/wiki/Base32";

    public override CipherResult Process(CipherRequest r) => r.Direction == CipherDirection.Encode
        ? new CipherResult(Primitives.Base32(InputBytes(r)))
        : new CipherResult(Primitives.Utf8.GetString(Primitives.Unbase32(r.Input)));
}

public sealed class Base58Method : EncodingMethod
{
    public override string Id => "base58";
    public override string Name => "Base58";
    public override string Blurb => "Bitcoin's alphabet: no 0, O, I or l, safe to read and dictate.";
    public override string Learn =>
        "Base58 drops the characters people misread (zero, capital O, capital I, lowercase L) " +
        "from the Base64 alphabet. Bitcoin addresses, IPFS hashes and private key WIF strings " +
        "use it. There is no padding and no + or /, so it also survives double-click selection.";
    public override string WikiUrl => "https://en.wikipedia.org/wiki/Base58";

    public override CipherResult Process(CipherRequest r) => r.Direction == CipherDirection.Encode
        ? new CipherResult(Primitives.Base58(InputBytes(r)))
        : new CipherResult(Primitives.Utf8.GetString(Primitives.Unbase58(r.Input)));
}

public sealed class HexMethod : EncodingMethod
{
    public override string Id => "hex";
    public override string Name => "Hexadecimal";
    public override string Blurb => "Every byte as two hex digits, the classic dump format.";
    public override string Learn =>
        "Hex maps each byte to two characters from 0-9 and a-f. It is the native language of " +
        "debuggers, cryptographic output and packet captures because you can see every single " +
        "bit position. 41 is 'A' in ASCII, 0x41 in hex, 01000001 in binary.";
    public override string WikiUrl => "https://en.wikipedia.org/wiki/Hexadecimal";
    public override IReadOnlyList<string> Aliases => new[] { "base16" };

    public override CipherResult Process(CipherRequest r) => r.Direction == CipherDirection.Encode
        ? new CipherResult(Primitives.Hex(InputBytes(r)))
        : new CipherResult(Primitives.Utf8.GetString(Primitives.Unhex(r.Input)));
}

public sealed class UrlMethod : EncodingMethod
{
    public override string Id => "url";
    public override string Name => "URL Encoding";
    public override string Blurb => "Percent-encoding for text that travels inside a URL.";
    public override string Learn =>
        "URLs may only carry a limited set of characters, so anything else gets replaced with " +
        "a percent sign followed by the byte's hex value. A space becomes %20, an emoji becomes " +
        "four byte escapes. Note that a plus sign is NOT a space in strict RFC 3986 encoding, " +
        "that habit comes from old HTML form encoding.";
    public override string WikiUrl => "https://en.wikipedia.org/wiki/Percent-encoding";
    public override IReadOnlyList<string> Aliases => new[] { "percent", "uri" };

    public override CipherResult Process(CipherRequest r) => r.Direction == CipherDirection.Encode
        ? new CipherResult(Uri.EscapeDataString(r.Input))
        : new CipherResult(Uri.UnescapeDataString(r.Input));
}

public sealed class BinaryMethod : EncodingMethod
{
    public override string Id => "binary";
    public override string Name => "Binary (text to bits)";
    public override string Blurb => "Turns text into raw 0s and 1s, one byte at a time.";
    public override string Learn =>
        "This shows what the computer actually stores: each character becomes its byte value, " +
        "each byte eight bits. 'Hi' is 72 and 105 in decimal, 01001000 and 01101001 in binary. " +
        "UTF-8 text with accents or emoji needs more than one byte per character, and you will " +
        "see exactly where the bytes split.";
    public override string WikiUrl => "https://en.wikipedia.org/wiki/Binary-to-text_encoding";

    public override CipherResult Process(CipherRequest r) => r.Direction == CipherDirection.Encode
        ? new CipherResult(Primitives.ToBinary(InputBytes(r)))
        : new CipherResult(Primitives.Utf8.GetString(Primitives.FromBinary(r.Input)));
}

public sealed class MorseMethod : EncodingMethod
{
    public override string Id => "morse";
    public override string Name => "Morse Code";
    public override string Blurb => "Dots and dashes, the original digital encoding.";
    public override string Learn =>
        "Morse code from the 1840s encodes each letter as short and long signals. In written " +
        "form, letters are separated by spaces and words by a slash. It is a variable-length " +
        "code designed so the most common English letters (E, T) get the shortest symbols, " +
        "an idea that later inspired Huffman coding.";
    public override string WikiUrl => "https://en.wikipedia.org/wiki/Morse_code";

    private static readonly Dictionary<char, string> Table = new()
    {
        ['a'] = ".-",    ['b'] = "-...",  ['c'] = "-.-.", ['d'] = "-..",
        ['e'] = ".",     ['f'] = "..-.",  ['g'] = "--.",  ['h'] = "....",
        ['i'] = "..",    ['j'] = ".---",  ['k'] = "-.-",  ['l'] = ".-..",
        ['m'] = "--",    ['n'] = "-.",    ['o'] = "---",  ['p'] = ".--.",
        ['q'] = "--.-",  ['r'] = ".-.",   ['s'] = "...",  ['t'] = "-",
        ['u'] = "..-",   ['v'] = "...-",  ['w'] = ".--",  ['x'] = "-..-",
        ['y'] = "-.--",  ['z'] = "--..",
        ['0'] = "-----", ['1'] = ".----", ['2'] = "..---", ['3'] = "...--",
        ['4'] = "....-", ['5'] = ".....", ['6'] = "-....", ['7'] = "--...",
        ['8'] = "---..", ['9'] = "----.",
        ['.'] = ".-.-.-", [','] = "--..--", ['?'] = "..--..", ['\''] = ".----.",
        ['!'] = "-.-.--", ['/'] = "-..-.",  ['('] = "-.--.",  [')'] = "-.--.-",
        ['&'] = ".-...",  [':'] = "---...", [';'] = "-.-.-.", ['='] = "-...-",
        ['+'] = ".-.-.",  ['-'] = "-....-", ['"'] = ".-..-.", ['@'] = ".--.-.",
        ['_'] = "..--.-",
    };

    private static readonly Dictionary<string, char> Reverse =
        Table.ToDictionary(kv => kv.Value, kv => kv.Key);

    public override CipherResult Process(CipherRequest r)
    {
        if (r.Direction == CipherDirection.Encode)
        {
            var sb = new StringBuilder();
            foreach (var word in r.Input.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                if (sb.Length > 0)
                    sb.Append(" / ");
                foreach (var ch in word)
                {
                    if (!Table.TryGetValue(char.ToLowerInvariant(ch), out var code))
                        throw new CipherException($"Morse has no symbol for '{ch}'.");
                    sb.Append(code).Append(' ');
                }
            }
            return new CipherResult(sb.ToString().TrimEnd());
        }

        var output = new StringBuilder();
        foreach (var word in r.Input.Replace('\n', ' ').Split(new[] { " / ", "/" }, StringSplitOptions.None))
        {
            foreach (var letter in word.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                if (!Reverse.TryGetValue(letter, out var ch))
                    throw new CipherException($"Unknown Morse sequence '{letter}'.");
                output.Append(ch);
            }
            output.Append(' ');
        }
        return new CipherResult(output.ToString().TrimEnd());
    }
}
