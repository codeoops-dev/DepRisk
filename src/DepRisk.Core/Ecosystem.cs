using DepRisk.Core.Versioning;

namespace DepRisk.Core;

/// <summary>
/// A package ecosystem DepRisk can read: how it is named in result files, how OSV names it, and which version
/// strings count as valid for it. Ecosystems are a closed set (ADR 0010); adding one is a deliberate change.
/// </summary>
public sealed class Ecosystem
{
    /// <summary>NuGet: <c>project.assets.json</c>, versions are NuGet versions (SemVer 2 plus an optional fourth part).</summary>
    public static readonly Ecosystem NuGet = new("nuget", "NuGet", "NuGet", strictSemVer: false);

    /// <summary>npm: <c>package-lock.json</c>, versions are strict SemVer 2.0 (exactly three numeric parts).</summary>
    public static readonly Ecosystem Npm = new("npm", "npm", "npm", strictSemVer: true);

    private readonly bool _strictSemVer;

    private Ecosystem(string id, string osvName, string displayName, bool strictSemVer)
    {
        Id = id;
        OsvName = osvName;
        DisplayName = displayName;
        _strictSemVer = strictSemVer;
    }

    public static IReadOnlyList<Ecosystem> All { get; } = [NuGet, Npm];

    /// <summary>The identifier used in result files and on the command line (<c>nuget</c>, <c>npm</c>).</summary>
    public string Id { get; }

    /// <summary>The ecosystem name OSV uses in <c>affected[].package.ecosystem</c> (matched exactly, ignoring case).</summary>
    public string OsvName { get; }

    /// <summary>The name shown to people.</summary>
    public string DisplayName { get; }

    public static bool TryFromId(string? id, out Ecosystem? ecosystem)
    {
        ecosystem = All.FirstOrDefault(e => string.Equals(e.Id, id, StringComparison.Ordinal));
        return ecosystem is not null;
    }

    /// <summary>Like <see cref="TryFromId"/>, but throws for an identifier that is not an ecosystem (for data that must be one).</summary>
    public static Ecosystem FromId(string id) =>
        TryFromId(id, out Ecosystem? ecosystem) && ecosystem is not null
            ? ecosystem
            : throw new ArgumentException($"'{id}' is not a known ecosystem.", nameof(id));

    /// <summary>
    /// Parses a version of this ecosystem. For npm the text must be a valid SemVer 2.0 version: three numeric parts without
    /// leading zeros, numeric prerelease identifiers without leading zeros, no leading "v", no ranges. Ordering and equality
    /// use <see cref="NuGetVersion"/>, which implements SemVer 2.0 precedence; the one known difference is that it compares
    /// alphanumeric prerelease identifiers ignoring case, where SemVer compares them as plain ASCII (ADR 0010).
    /// </summary>
    public bool TryParseVersion(string? text, out NuGetVersion? version)
    {
        version = null;

        if (_strictSemVer && !IsStrictSemVer(text))
        {
            return false;
        }

        return NuGetVersion.TryParse(text, out version);
    }

    public override string ToString() => Id;

    private static bool IsStrictSemVer(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        string rest = text;
        int plus = rest.IndexOf('+', StringComparison.Ordinal);

        if (plus >= 0)
        {
            if (!AllIdentifiers(rest[(plus + 1)..], allowLeadingZeros: true))
            {
                return false;
            }

            rest = rest[..plus];
        }

        int dash = rest.IndexOf('-', StringComparison.Ordinal);

        if (dash >= 0)
        {
            if (!AllIdentifiers(rest[(dash + 1)..], allowLeadingZeros: false))
            {
                return false;
            }

            rest = rest[..dash];
        }

        string[] parts = rest.Split('.');

        return parts.Length == 3 && parts.All(IsNumericWithoutLeadingZeros);
    }

    /// <summary>Dot-separated identifiers of [0-9A-Za-z-]; numeric ones must not have leading zeros (prerelease only).</summary>
    private static bool AllIdentifiers(string text, bool allowLeadingZeros)
    {
        if (text.Length == 0)
        {
            return false;
        }

        foreach (string identifier in text.Split('.'))
        {
            if (identifier.Length == 0 || !identifier.All(c => char.IsAsciiLetterOrDigit(c) || c == '-'))
            {
                return false;
            }

            if (!allowLeadingZeros && identifier.All(char.IsAsciiDigit) && !IsNumericWithoutLeadingZeros(identifier))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsNumericWithoutLeadingZeros(string part) =>
        part.Length > 0
        && part.All(char.IsAsciiDigit)
        && (part.Length == 1 || part[0] != '0');
}
