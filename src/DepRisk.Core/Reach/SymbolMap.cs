namespace DepRisk.Core.Reach;

/// <summary>
/// What is known about how one advisory is reached in one package: the public entry points (<see cref="Symbols"/>) through
/// which application code can reach the flaw. <see cref="Complete"/> says the list is claimed to have all of them; the
/// analyzer only ever says "unreachable" when it is true. <see cref="Sources"/> is where the list comes from (provenance).
/// </summary>
public sealed record SymbolSet(string Advisory, string Package, IReadOnlyList<string> Symbols, bool Complete, IReadOnlyList<string> Sources);

/// <summary>All symbol sets of the loaded maps, merged by advisory and package.</summary>
public sealed class SymbolMap
{
    private readonly Dictionary<(string Advisory, string Package), SymbolSet> _sets;

    public SymbolMap(IEnumerable<SymbolSet> sets)
    {
        ArgumentNullException.ThrowIfNull(sets);
        _sets = new Dictionary<(string, string), SymbolSet>();

        foreach (SymbolSet set in sets)
        {
            (string, string) key = (set.Advisory.ToUpperInvariant(), set.Package.ToUpperInvariant());
            _sets[key] = _sets.TryGetValue(key, out SymbolSet? existing) ? Merge(existing, set) : set;
        }
    }

    public int Count => _sets.Count;

    public IEnumerable<SymbolSet> Sets => _sets.Values.OrderBy(s => s.Advisory, StringComparer.Ordinal).ThenBy(s => s.Package, StringComparer.Ordinal);

    /// <summary>
    /// The symbols known for a finding: the entries for its advisory id or any alias, for this package, merged. Two entries
    /// for the same flaw are combined conservatively: the symbols of both, and complete only if both claim it.
    /// </summary>
    public SymbolSet? Find(IEnumerable<string> advisoryIds, string package)
    {
        SymbolSet? merged = null;

        foreach (string id in advisoryIds.Select(i => i.ToUpperInvariant()).Distinct(StringComparer.Ordinal))
        {
            if (_sets.TryGetValue((id, package.ToUpperInvariant()), out SymbolSet? set))
            {
                merged = merged is null ? set : Merge(merged, set);
            }
        }

        return merged;
    }

    private static SymbolSet Merge(SymbolSet a, SymbolSet b) =>
        new(
            a.Advisory,
            a.Package,
            a.Symbols.Concat(b.Symbols).Distinct(StringComparer.Ordinal).OrderBy(s => s, StringComparer.Ordinal).ToList(),
            a.Complete && b.Complete,
            a.Sources.Concat(b.Sources).Distinct(StringComparer.Ordinal).OrderBy(s => s, StringComparer.Ordinal).ToList());
}
