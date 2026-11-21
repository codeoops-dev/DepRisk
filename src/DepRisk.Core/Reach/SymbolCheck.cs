using DepRisk.Core.Model;

namespace DepRisk.Core.Reach;

public enum SymbolEntryStatus
{
    /// <summary>The entry matches a finding of the project.</summary>
    Applies,

    /// <summary>No finding of the project matches the entry.</summary>
    Unused,
}

/// <param name="Direct">Meaningful when the entry applies: the package is a direct dependency somewhere it matches.</param>
public sealed record SymbolEntryCheck(string Advisory, string Package, bool Complete, IReadOnlyList<string> Sources, SymbolEntryStatus Status, bool Direct);

/// <param name="IgnoredOtherLanguage">Entries of the other language: counted, not judged.</param>
/// <param name="Pairs">The advisory and package pairs of the project and what each needs (see <see cref="SymbolTemplate"/>).</param>
public sealed record SymbolCheckResult(IReadOnlyList<SymbolEntryCheck> Entries, int IgnoredOtherLanguage, IReadOnlyList<SymbolWorkItem> Pairs)
{
    public int Applies => Entries.Count(e => e.Status == SymbolEntryStatus.Applies);

    public int Unused => Entries.Count(e => e.Status == SymbolEntryStatus.Unused);

    public int Incomplete => Entries.Count(e => e.Status == SymbolEntryStatus.Applies && !e.Complete);

    public int CompleteButTransitive => Entries.Count(e => e.Status == SymbolEntryStatus.Applies && e.Complete && !e.Direct);

    public int Missing => Pairs.Count(p => p.Status == SymbolWorkStatus.Missing);

    public int Unwritable => Pairs.Count(p => p.Status == SymbolWorkStatus.Unwritable);
}

/// <summary>
/// Does a set of symbol maps still fit a project (ADR 0025)? Pure: no IO. An entry is found for a finding exactly as
/// <c>reach</c> looks it up (advisory id or any alias, and package, ignoring case, in the project's language).
/// </summary>
public static class SymbolCheck
{
    public static readonly IReadOnlyList<string> GateTerms = ["missing", "incomplete", "unused"];

    public static SymbolCheckResult Evaluate(IEnumerable<Finding> findings, SymbolMap map, string language)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(map);

        if (!SymbolLanguages.IsKnown(language))
        {
            throw new ArgumentException("unknown symbol language", nameof(language));
        }

        List<Finding> all = findings.ToList();
        List<SymbolEntryCheck> entries = [];

        foreach (SymbolSet set in map.Sets.Where(s => s.Language == language))
        {
            List<Finding> matching = all
                .Where(f => string.Equals(f.Package.Id, set.Package, StringComparison.OrdinalIgnoreCase)
                    && (string.Equals(f.Id, set.Advisory, StringComparison.OrdinalIgnoreCase)
                        || f.Aliases.Any(a => string.Equals(a, set.Advisory, StringComparison.OrdinalIgnoreCase))))
                .ToList();

            entries.Add(new SymbolEntryCheck(
                set.Advisory,
                set.Package,
                set.Complete,
                set.Sources,
                matching.Count > 0 ? SymbolEntryStatus.Applies : SymbolEntryStatus.Unused,
                matching.Any(f => f.Locations.Any(l => l.IsDirect))));
        }

        return new SymbolCheckResult(entries, map.Count - map.CountFor(language), SymbolTemplate.Plan(all, map, language));
    }

    /// <summary>Reads <c>--fail-on</c>: a comma-separated list of <see cref="GateTerms"/>. Anything else is an input error.</summary>
    public static IReadOnlySet<string> ParseGate(string expression)
    {
        ArgumentNullException.ThrowIfNull(expression);
        HashSet<string> terms = new(StringComparer.Ordinal);

        foreach (string raw in expression.Split(','))
        {
            string term = raw.Trim();

            if (!GateTerms.Contains(term, StringComparer.Ordinal))
            {
                throw new InvalidInputException($"--fail-on '{SafeText.Clean(term, 40)}' is not a condition of 'symbols check' (use: {string.Join(", ", GateTerms)}).");
            }

            terms.Add(term);
        }

        return terms;
    }

    /// <summary>The conditions of the gate that hold, with their counts, in the order of <see cref="GateTerms"/>; empty if the gate passes.</summary>
    public static IReadOnlyList<string> Tripped(SymbolCheckResult result, IReadOnlySet<string> gate)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(gate);
        List<string> tripped = [];

        foreach (string term in GateTerms.Where(gate.Contains))
        {
            int count = term switch
            {
                "missing" => result.Missing,
                "incomplete" => result.Incomplete,
                _ => result.Unused,
            };

            if (count > 0)
            {
                tripped.Add($"{term}: {count}");
            }
        }

        return tripped;
    }
}
