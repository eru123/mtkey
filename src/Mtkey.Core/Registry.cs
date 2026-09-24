namespace Mtkey.Core;

/// <summary>Every cipher method the app knows, in display order.</summary>
public static class Registry
{
    private static readonly List<CipherMethod> Methods = Build();

    private static List<CipherMethod> Build()
    {
        var list = new List<CipherMethod>
        {
            new Base64Method(),
            new Base32Method(),
            new Base58Method(),
            new HexMethod(),
            new UrlMethod(),
            new BinaryMethod(),
            new MorseMethod(),

            new CaesarMethod(),
            new Rot13Method(),
            new AtbashMethod(),
            new VigenereMethod(),
            new RailFenceMethod(),
            new PlayfairMethod(),
            new XorMethod(),
        };
        list.AddRange(HashMethods.All());
        list.AddRange(ModernMethods.All());
        list.AddRange(DefuseMethods.All());
        list.AddRange(TokenMethods.All());
        return list;
    }

    public static IReadOnlyList<CipherMethod> All => Methods;

    public static CipherMethod? Find(string idOrName) =>
        Methods.FirstOrDefault(m =>
            m.Id.Equals(idOrName, StringComparison.OrdinalIgnoreCase) ||
            m.Name.Equals(idOrName, StringComparison.OrdinalIgnoreCase));

    /// <summary>Search across name, aliases and category, the fuel for the
    /// type-to-filter selector.</summary>
    public static IEnumerable<CipherMethod> Search(string text)
    {
        var q = text.Trim();
        if (q.Length == 0)
            return Methods;
        var terms = q.ToLowerInvariant().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return Methods.Where(m =>
        {
            var haystack = new[] { m.Name, m.Id, m.Category }
                .Concat(m.Aliases)
                .Select(s => s.ToLowerInvariant())
                .ToArray();
            return terms.All(t => haystack.Any(h => h.Contains(t)));
        });
    }
}
