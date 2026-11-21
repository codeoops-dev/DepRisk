using DepRisk.Core.Model;

namespace DepRisk.Core.Reach;

/// <summary>What a <see cref="SymbolWorkItem"/> needs from the person who writes symbol maps.</summary>
public enum SymbolWorkStatus
{
    /// <summary>No symbol map entry exists for the advisory and package: an entry has to be written.</summary>
    Missing,

    /// <summary>An entry exists (it may still be incomplete): nothing is drafted.</summary>
    Covered,

    /// <summary>The advisory id or package name cannot be written as a symbol map entry (see <see cref="SymbolWorkItem.Problem"/>).</summary>
    Unwritable,
}

/// <summary>
/// One advisory in one package, whatever the installed versions, as <c>reach</c> asks about it (one question per advisory and package,
/// ADR 0013). The text fields come from the advisory database and are untrusted data.
/// </summary>
public sealed record SymbolWorkItem(
    string Advisory,
    IReadOnlyList<string> Aliases,
    string Package,
    IReadOnlyList<string> InstalledVersions,
    bool Direct,
    string? Summary,
    IReadOnlyList<string> FixedVersions,
    SymbolWorkStatus Status,
    bool ExistingComplete,
    string? Problem);

/// <summary>
/// Plans the work of writing symbol maps (ADR 0024): which advisory and package pairs of a project have no entry yet. Pure: no IO.
/// It never proposes symbols. OSV carries none for NuGet or npm, and a guessed symbol would be a claim nobody made.
/// </summary>
public static class SymbolTemplate
{
    private const int MaxAdvisoryLength = 100;
    private const int MaxPackageLength = 200;

    /// <summary>
    /// One item per advisory id and package of the findings, in a fixed order (advisory, then package, ordinal). A pair is
    /// <see cref="SymbolWorkStatus.Covered"/> when <paramref name="existing"/> has an entry for the id or any alias, in
    /// <paramref name="language"/>, exactly as <c>reach</c> looks it up.
    /// </summary>
    public static IReadOnlyList<SymbolWorkItem> Plan(IEnumerable<Finding> findings, SymbolMap? existing, string language)
    {
        ArgumentNullException.ThrowIfNull(findings);

        if (!SymbolLanguages.IsKnown(language))
        {
            throw new ArgumentException("unknown symbol language", nameof(language));
        }

        List<SymbolWorkItem> items = [];

        foreach (IGrouping<(string Id, string Package), Finding> group in findings
            .GroupBy(f => (Id: f.Id, Package: f.Package.Id))
            .OrderBy(g => g.Key.Id, StringComparer.Ordinal)
            .ThenBy(g => g.Key.Package, StringComparer.Ordinal))
        {
            string id = group.Key.Id;
            string package = group.Key.Package;

            List<string> aliases = group
                .SelectMany(f => f.Aliases)
                .Where(a => !string.Equals(a, id, StringComparison.OrdinalIgnoreCase))
                .Distinct(StringComparer.Ordinal)
                .OrderBy(a => a, StringComparer.Ordinal)
                .ToList();

            List<string> versions = group.Select(f => f.Package.Version).Distinct(StringComparer.Ordinal).OrderBy(v => v, StringComparer.Ordinal).ToList();
            List<string> fixedVersions = group.SelectMany(f => f.FixedVersions).Distinct(StringComparer.Ordinal).OrderBy(v => v, StringComparer.Ordinal).ToList();
            bool direct = group.Any(f => f.Locations.Any(l => l.IsDirect));
            string? summary = group.Select(f => f.Summary).FirstOrDefault(s => !string.IsNullOrWhiteSpace(s));

            SymbolSet? set = existing?.Find([id, .. aliases], package, language);
            string? problem = set is null ? ProblemOf(id, package, language) : null;

            SymbolWorkStatus status = set is not null ? SymbolWorkStatus.Covered : problem is not null ? SymbolWorkStatus.Unwritable : SymbolWorkStatus.Missing;

            items.Add(new SymbolWorkItem(id, aliases, package, versions, direct, summary, fixedVersions, status, set?.Complete ?? false, problem));
        }

        return items;
    }

    /// <summary>Why an advisory id and package cannot be an entry of a symbol map of this language; null if they can.</summary>
    internal static string? ProblemOf(string advisory, string package, string language)
    {
        if (advisory.Length is 0 or > MaxAdvisoryLength || !advisory.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or ':' or '-'))
        {
            return "the advisory id has characters or a length a symbol map does not accept";
        }

        bool javascript = language == SymbolLanguages.JavaScript;

        bool packageChars = package.Length is > 0 and <= MaxPackageLength
            && package.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-' || (javascript && c is '@' or '/' or '~'));

        if (!packageChars || (javascript && !SymbolSyntax.IsValidJsPackage(package)))
        {
            return "the package name has characters or a length a symbol map does not accept";
        }

        return null;
    }
}
