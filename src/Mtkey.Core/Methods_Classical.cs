using System.Text;

namespace Mtkey.Core;

public abstract class ClassicalMethod : CipherMethod
{
    public override string Category => "Classical";
}

public sealed class CaesarMethod : ClassicalMethod
{
    public override string Id => "caesar";
    public override string Name => "Caesar Cipher";
    public override string Blurb => "Shift every letter along the alphabet by a fixed amount.";
    public override string Learn =>
        "Julius Caesar reportedly shifted letters by 3 to hide messages. Each letter moves a " +
        "fixed number of places along the alphabet and wraps around, so with shift 3, CAT " +
        "becomes FDW. There are only 25 possible shifts, which is why you can break it by " +
        "trying them all, a technique called brute force.";
    public override string WikiUrl => "https://en.wikipedia.org/wiki/Caesar_cipher";

    public override IReadOnlyList<FieldSpec> Fields { get; } = new[]
    {
        new FieldSpec
        {
            Name = "shift",
            Label = "Shift",
            Kind = FieldKind.Number,
            Default = "3",
            Min = 0,
            Max = 25,
            Hint = "How many letters to slide (0-25). Try 3 for the classic Caesar.",
            Generator = GeneratorKind.Number,
            GeneratorRange = (1, 25),
        },
    };

    public override CipherResult Process(CipherRequest r)
    {
        var shift = ParseShift(r.Field("shift"));
        var effective = r.Direction == CipherDirection.Encode ? shift : 26 - shift;
        var sb = new StringBuilder();
        foreach (var c in r.Input)
        {
            if (c is >= 'A' and <= 'Z')
                sb.Append((char)('A' + (c - 'A' + effective) % 26));
            else if (c is >= 'a' and <= 'z')
                sb.Append((char)('a' + (c - 'a' + effective) % 26));
            else
                sb.Append(c);
        }
        return new CipherResult(sb.ToString());
    }

    private static int ParseShift(string text)
    {
        if (!int.TryParse(text.Trim(), out var shift) || shift is < 0 or > 25)
            throw new CipherException("Shift must be a number from 0 to 25.");
        return shift;
    }
}

public sealed class Rot13Method : ClassicalMethod
{
    public override string Id => "rot13";
    public override string Name => "ROT13";
    public override string Blurb => "Caesar with shift 13. Applying it twice brings the text back.";
    public override string Learn =>
        "ROT13 shifts letters by 13, exactly half the alphabet, so encoding and decoding are " +
        "the same operation. Usenet forums used it to hide spoilers and punchlines: the reader " +
        "who wants the spoiler runs the text through ROT13, everyone else skips it. It is a " +
        "prime example of obfuscation, not security.";
    public override string WikiUrl => "https://en.wikipedia.org/wiki/ROT13";

    public override CipherResult Process(CipherRequest r)
    {
        var sb = new StringBuilder();
        foreach (var c in r.Input)
        {
            if (c is >= 'A' and <= 'Z')
                sb.Append((char)('A' + (c - 'A' + 13) % 26));
            else if (c is >= 'a' and <= 'z')
                sb.Append((char)('a' + (c - 'a' + 13) % 26));
            else
                sb.Append(c);
        }
        return new CipherResult(sb.ToString());
    }
}

public sealed class AtbashMethod : ClassicalMethod
{
    public override string Id => "atbash";
    public override string Name => "Atbash";
    public override string Blurb => "Mirrors the alphabet: A becomes Z, B becomes Y, and so on.";
    public override string Learn =>
        "Atbash reverses the alphabet, mapping A to Z and B to Y. It appears in the Hebrew " +
        "Book of Jeremiah from the 6th century BC, making it one of the oldest ciphers we " +
        "know of. Like ROT13 it is its own inverse, and like every classical cipher it offers " +
        "zero real security today.";
    public override string WikiUrl => "https://en.wikipedia.org/wiki/Atbash";

    public override CipherResult Process(CipherRequest r)
    {
        var sb = new StringBuilder();
        foreach (var c in r.Input)
        {
            if (c is >= 'A' and <= 'Z')
                sb.Append((char)('Z' - (c - 'A')));
            else if (c is >= 'a' and <= 'z')
                sb.Append((char)('z' - (c - 'a')));
            else
                sb.Append(c);
        }
        return new CipherResult(sb.ToString());
    }
}

public sealed class VigenereMethod : ClassicalMethod
{
    public override string Id => "vigenere";
    public override string Name => "Vigenère Cipher";
    public override string Blurb => "A rolling Caesar: each letter shifts by the next letter of a keyword.";
    public override string Learn =>
        "The Vigenère cipher uses a keyword as a table of shifts: the first plaintext letter " +
        "moves by the keyword's first letter, the second by the second, looping the keyword " +
        "as needed. For 300 years it was called le chiffre indéchiffrable until Kasiski and " +
        "Babbage showed that repeated keywords leak the key length through repeated patterns.";
    public override string WikiUrl => "https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher";
    public override IReadOnlyList<string> Aliases => new[] { "vigenere" };

    public override IReadOnlyList<FieldSpec> Fields { get; } = new[]
    {
        new FieldSpec
        {
            Name = "key",
            Label = "Keyword",
            Placeholder = "SECRET",
            Hint = "Only letters count. A longer keyword means a stronger shift pattern.",
            Generator = GeneratorKind.Password,
            GeneratorSize = 8,
        },
    };

    public override CipherResult Process(CipherRequest r)
    {
        var key = r.Field("key").Where(char.IsLetter).Select(char.ToLowerInvariant).ToArray();
        if (key.Length == 0)
            throw new CipherException("The keyword needs at least one letter.");
        var sign = r.Direction == CipherDirection.Encode ? 1 : -1;

        var sb = new StringBuilder();
        var ki = 0;
        foreach (var c in r.Input)
        {
            if (c is >= 'A' and <= 'Z')
            {
                sb.Append((char)('A' + Mod(c - 'A' + sign * (key[ki] - 'a'), 26)));
                ki = (ki + 1) % key.Length;
            }
            else if (c is >= 'a' and <= 'z')
            {
                sb.Append((char)('a' + Mod(c - 'a' + sign * (key[ki] - 'a'), 26)));
                ki = (ki + 1) % key.Length;
            }
            else
                sb.Append(c);
        }
        return new CipherResult(sb.ToString());
    }

    private static int Mod(int v, int m) => ((v % m) + m) % m;
}

public sealed class RailFenceMethod : ClassicalMethod
{
    public override string Id => "railfence";
    public override string Name => "Rail Fence";
    public override string Blurb => "Writes text in a zigzag across N rails, reads it row by row.";
    public override string Learn =>
        "A transposition cipher: the letters never change, only their order does. You write " +
        "the message diagonally up and down across a number of rails, then read each rail " +
        "left to right. WEAREDISCOVERED on 3 rails becomes WECRLTEERDSOEE. Transposition " +
        "pairs naturally with substitution ciphers, stacking both is how Enigma-era systems " +
        "were built.";
    public override string WikiUrl => "https://en.wikipedia.org/wiki/Rail_fence_cipher";
    public override IReadOnlyList<string> Aliases => new[] { "zigzag" };

    public override IReadOnlyList<FieldSpec> Fields { get; } = new[]
    {
        new FieldSpec
        {
            Name = "rails",
            Label = "Rails",
            Kind = FieldKind.Number,
            Default = "3",
            Min = 2,
            Max = 20,
            Hint = "Number of zigzag rows. Both sides need the same count.",
            Generator = GeneratorKind.Number,
            GeneratorRange = (2, 8),
        },
    };

    public override CipherResult Process(CipherRequest r)
    {
        if (!int.TryParse(r.Field("rails").Trim(), out var rails) || rails < 2 || rails > 20)
            throw new CipherException("Rails must be a number from 2 to 20.");
        var text = r.Input;
        if (text.Length == 0)
            return new CipherResult("");

        var pattern = Zigzag(text.Length, rails);
        if (r.Direction == CipherDirection.Encode)
        {
            var sb = new StringBuilder();
            for (var rail = 0; rail < rails; rail++)
                for (var i = 0; i < text.Length; i++)
                    if (pattern[i] == rail)
                        sb.Append(text[i]);
            return new CipherResult(sb.ToString());
        }
        else
        {
            var result = new char[text.Length];
            var source = 0;
            for (var rail = 0; rail < rails; rail++)
                for (var i = 0; i < text.Length; i++)
                    if (pattern[i] == rail)
                        result[i] = text[source++];
            return new CipherResult(new string(result));
        }
    }

    private static int[] Zigzag(int length, int rails)
    {
        var pattern = new int[length];
        var rail = 0;
        var step = 1;
        for (var i = 0; i < length; i++)
        {
            pattern[i] = rail;
            if (rail == 0) step = 1;
            else if (rail == rails - 1) step = -1;
            rail += step;
        }
        return pattern;
    }
}

public sealed class XorMethod : ClassicalMethod
{
    public override string Id => "xor";
    public override string Name => "XOR Cipher";
    public override string Blurb => "XORs every byte with a repeating key. Output arrives as hex.";
    public override string Learn =>
        "XOR is the atom of cryptography: a bit flipped twice comes back, so the same " +
        "operation encrypts and decrypts. One-Time Pads (a random key as long as the message) " +
        "are provably unbreakable this way. Repeating a short key instead is the Vigenère " +
        "mistake all over again, and that is what cracks messages like the Enigma-era " +
        "diplomatic cables.";
    public override string WikiUrl => "https://en.wikipedia.org/wiki/XOR_cipher";

    public override IReadOnlyList<FieldSpec> Fields { get; } = new[]
    {
        new FieldSpec
        {
            Name = "key",
            Label = "Key",
            Placeholder = "secret",
            Hint = "Repeated over the message. Encode reads the key as text, one letter per byte.",
            Generator = GeneratorKind.Password,
            GeneratorSize = 16,
        },
    };

    public override string EncodeLabel => "Encode to hex";
    public override string DecodeLabel => "Decode from hex";

    public override CipherResult Process(CipherRequest r)
    {
        var key = Primitives.Utf8.GetBytes(r.Field("key"));
        if (key.Length == 0)
            throw new CipherException("XOR needs a key.");

        if (r.Direction == CipherDirection.Encode)
        {
            var data = Primitives.Utf8.GetBytes(r.Input);
            return new CipherResult(Primitives.Hex(Xor(data, key)));
        }
        else
        {
            var data = Primitives.Unhex(r.Input);
            return new CipherResult(Primitives.Utf8.GetString(Xor(data, key)));
        }
    }

    private static byte[] Xor(byte[] data, byte[] key)
    {
        var output = new byte[data.Length];
        for (var i = 0; i < data.Length; i++)
            output[i] = (byte)(data[i] ^ key[i % key.Length]);
        return output;
    }
}

public sealed class PlayfairMethod : ClassicalMethod
{
    public override string Id => "playfair";
    public override string Name => "Playfair Cipher";
    public override string Blurb => "Digraph cipher from a 5x5 keyword square, I and J share a cell.";
    public override string Learn =>
        "Playfair encrypts letter PAIRS using a 5x5 square built from a keyword (I and J " +
        "share one cell). Same-row letters shift right, same-column letters shift down, and " +
        "corner letters swap horizontally. Double letters get an X between them and an odd " +
        "tail gets an X appended, so decryption cannot always undo those insertions perfectly: " +
        "you may see an extra X or a split double letter in the result. It was the first " +
        "practical digraph cipher and saw duty in the Boer War and WWI.";
    public override string WikiUrl => "https://en.wikipedia.org/wiki/Playfair_cipher";

    public override IReadOnlyList<FieldSpec> Fields { get; } = new[]
    {
        new FieldSpec
        {
            Name = "key",
            Label = "Keyword",
            Placeholder = "MONARCHY",
            Hint = "Builds the 5x5 square. Letters only, J folds into I.",
            Generator = GeneratorKind.Password,
            GeneratorSize = 8,
        },
    };

    public override CipherResult Process(CipherRequest r)
    {
        var square = BuildSquare(r.Field("key"));
        var text = new string(r.Input.Where(char.IsLetter).Select(char.ToUpperInvariant).ToArray());
        if (text.Length == 0)
            return new CipherResult("");

        var pairs = SplitPairs(text);
        var encode = r.Direction == CipherDirection.Encode;
        var sb = new StringBuilder();
        foreach (var (a, b) in pairs)
        {
            Find(square, a, out var r1, out var c1);
            Find(square, b, out var r2, out var c2);
            if (r1 == r2)
            {
                sb.Append(square[r1, encode ? Shift(c1, 1) : Shift(c1, -1)]);
                sb.Append(square[r2, encode ? Shift(c2, 1) : Shift(c2, -1)]);
            }
            else if (c1 == c2)
            {
                sb.Append(square[encode ? Shift(r1, 1) : Shift(r1, -1), c1]);
                sb.Append(square[encode ? Shift(r2, 1) : Shift(r2, -1), c2]);
            }
            else
            {
                sb.Append(square[r1, c2]);
                sb.Append(square[r2, c1]);
            }
            sb.Append(' ');
        }
        return new CipherResult(sb.ToString().TrimEnd());
    }

    private static char[,] BuildSquare(string keyword)
    {
        var seen = new HashSet<char>();
        var letters = new List<char>();
        foreach (var c in keyword.ToUpperInvariant())
        {
            if (!char.IsLetter(c)) continue;
            var ch = c == 'J' ? 'I' : c;
            if (seen.Add(ch))
                letters.Add(ch);
        }
        for (var c = 'A'; c <= 'Z'; c++)
            if (c != 'J' && seen.Add(c))
                letters.Add(c);

        var square = new char[5, 5];
        for (var i = 0; i < 25; i++)
            square[i / 5, i % 5] = letters[i];
        return square;
    }

    private static List<(char A, char B)> SplitPairs(string text)
    {
        var cleaned = text.Replace('J', 'I');
        var pairs = new List<(char, char)>();
        var i = 0;
        while (i < cleaned.Length)
        {
            var a = cleaned[i];
            var b = i + 1 < cleaned.Length ? cleaned[i + 1] : 'X';
            if (a == b)
            {
                pairs.Add((a, 'X'));
                i++;
            }
            else
            {
                pairs.Add((a, b));
                i += 2;
            }
        }
        return pairs;
    }

    private static void Find(char[,] square, char c, out int row, out int col)
    {
        for (var r = 0; r < 5; r++)
            for (var cc = 0; cc < 5; cc++)
                if (square[r, cc] == c)
                {
                    row = r;
                    col = cc;
                    return;
                }
        throw new CipherException($"Character '{c}' cannot live in a Playfair square.");
    }

    private static int Shift(int v, int d) => ((v + d) % 5 + 5) % 5;
}
