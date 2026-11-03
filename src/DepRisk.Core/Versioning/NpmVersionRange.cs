using System.Text.RegularExpressions;

namespace DepRisk.Core.Versioning;

/// <summary>
/// An npm (node-semver) version range, for deciding whether an installed version satisfies a requirement.
/// Supported: exact versions, comparators (<c>&gt; &gt;= &lt; &lt;= =</c>), caret and tilde ranges, x-ranges and partial
/// versions (<c>1.x</c>, <c>1.2.*</c>, <c>1.2</c>, <c>*</c>, empty), hyphen ranges (<c>1.2.3 - 2.3.4</c>), AND (spaces) and
/// OR (<c>||</c>), an optional leading <c>v</c>, and <c>npm:name@range</c> aliases (see <see cref="TryParseSpec"/>).
/// Everything else (dist-tags such as <c>latest</c>, URLs, git and file specifiers, <c>workspace:</c>) is not understood:
/// <see cref="TryParse"/> returns false, and callers must treat the requirement as undecided, never as satisfied.
/// Semantics follow node-semver 7: a prerelease version satisfies a range only if a comparator of the same comparator set
/// has a prerelease on the same major.minor.patch, and generated upper bounds are written <c>&lt;X.0.0-0</c> so that
/// prereleases of the excluded version stay excluded. Not supported: <c>includePrerelease</c> and loose parsing.
/// </summary>
public sealed partial class NpmVersionRange
{
    private enum Op
    {
        Lt,
        Le,
        Gt,
        Ge,
        Eq,
    }

    private readonly record struct Comparator(Op Operator, NuGetVersion Version);

    private readonly List<List<Comparator>> _sets;

    private NpmVersionRange(List<List<Comparator>> sets) => _sets = sets;

    /// <summary>Parses a node-semver range. Null, tags, URLs, and anything not in the supported grammar return false.</summary>
    public static bool TryParse(string? text, out NpmVersionRange? range)
    {
        range = null;

        if (text is null || text.Length > 1000)
        {
            return false;
        }

        List<List<Comparator>> sets = [];

        foreach (string part in text.Split("||"))
        {
            if (!TryParseSet(part.Trim(), out List<Comparator>? set) || set is null)
            {
                return false;
            }

            sets.Add(set);
        }

        range = new NpmVersionRange(sets);
        return true;
    }

    /// <summary>
    /// Parses what a dependency declaration says: a range, or an alias <c>npm:name@range</c> whose range part is used
    /// (the installed package is the one under the alias key). <c>npm:name</c> without a range means a tag and is not understood.
    /// </summary>
    public static bool TryParseSpec(string? spec, out NpmVersionRange? range)
    {
        range = null;

        if (spec is not null && spec.StartsWith("npm:", StringComparison.Ordinal))
        {
            string target = spec[4..];
            int at = target.LastIndexOf('@');

            if (at <= 0)
            {
                return false;
            }

            return TryParse(target[(at + 1)..], out range);
        }

        return TryParse(spec, out range);
    }

    public bool Contains(NuGetVersion version)
    {
        ArgumentNullException.ThrowIfNull(version);

        return _sets.Any(set => SetContains(set, version));
    }

    private static bool SetContains(List<Comparator> set, NuGetVersion version)
    {
        foreach (Comparator comparator in set)
        {
            bool passes = comparator.Operator switch
            {
                Op.Lt => version < comparator.Version,
                Op.Le => version <= comparator.Version,
                Op.Gt => version > comparator.Version,
                Op.Ge => version >= comparator.Version,
                _ => version == comparator.Version,
            };

            if (!passes)
            {
                return false;
            }
        }

        if (!version.IsPrerelease)
        {
            return true;
        }

        // A prerelease is only allowed by a comparator that names a prerelease of the same major.minor.patch.
        return set.Any(c => c.Version.IsPrerelease
            && c.Version.Major == version.Major
            && c.Version.Minor == version.Minor
            && c.Version.Patch == version.Patch);
    }

    // --- parsing ---

    private static bool TryParseSet(string text, out List<Comparator>? set)
    {
        set = [];

        if (text.Length == 0)
        {
            return true;   // "" means any version
        }

        Match hyphen = HyphenPattern().Match(text);

        if (hyphen.Success)
        {
            return TryParseHyphen(hyphen.Groups[1].Value, hyphen.Groups[2].Value, set);
        }

        if (text.Contains(" - ", StringComparison.Ordinal))
        {
            set = null;
            return false;
        }

        // Operators may be separated from their version by spaces ("> 1.2.3", "^ 1.2").
        string normalized = OperatorSpacePattern().Replace(text, "$1");

        foreach (string token in normalized.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
        {
            if (!TryParseToken(token, set))
            {
                set = null;
                return false;
            }
        }

        return true;
    }

    private static bool TryParseToken(string token, List<Comparator> set)
    {
        string op = string.Empty;

        foreach (string candidate in new[] { ">=", "<=", ">", "<", "=", "~>", "~", "^" })
        {
            if (token.StartsWith(candidate, StringComparison.Ordinal))
            {
                op = candidate;
                token = token[candidate.Length..];
                break;
            }
        }

        if (!TryParsePartial(token, out Partial partial))
        {
            return false;
        }

        return op switch
        {
            "" or "=" => AddExact(partial, set),
            ">" => AddGreater(partial, orEqual: false, set),
            ">=" => AddGreater(partial, orEqual: true, set),
            "<" => AddLess(partial, orEqual: false, set),
            "<=" => AddLess(partial, orEqual: true, set),
            "~" or "~>" => AddTilde(partial, set),
            _ => AddCaret(partial, set),
        };
    }

    private static bool TryParseHyphen(string from, string to, List<Comparator> set)
    {
        if (!TryParsePartial(from, out Partial low) || !TryParsePartial(to, out Partial high))
        {
            return false;
        }

        // Lower bound: a partial version is filled with zeros; a wildcard lower bound is no bound.
        if (!low.IsAny)
        {
            if (!TryAdd(set, Op.Ge, low.Major, low.Minor ?? 0, low.Patch ?? 0, low.IsFull ? low.Prerelease : null))
            {
                return false;
            }
        }

        // Upper bound: a partial version allows everything below the next one; a full version is inclusive.
        if (high.IsAny)
        {
            return true;
        }

        if (high.IsFull)
        {
            return TryAdd(set, Op.Le, high.Major, high.Minor!.Value, high.Patch!.Value, high.Prerelease);
        }

        return high.Minor is null
            ? TryAdd(set, Op.Lt, high.Major + 1L, 0, 0, "0")
            : TryAdd(set, Op.Lt, high.Major, high.Minor.Value + 1L, 0, "0");
    }

    private static bool AddExact(Partial p, List<Comparator> set)
    {
        if (p.IsAny)
        {
            return true;
        }

        if (p.IsFull)
        {
            return TryAdd(set, Op.Eq, p.Major, p.Minor!.Value, p.Patch!.Value, p.Prerelease);
        }

        return AddRange(p, set);
    }

    /// <summary>The range covered by a partial version: 1.x is [1.0.0, 2.0.0-0), 1.2.x is [1.2.0, 1.3.0-0).</summary>
    private static bool AddRange(Partial p, List<Comparator> set) =>
        p.Minor is null
            ? TryAdd(set, Op.Ge, p.Major, 0, 0, null) && TryAdd(set, Op.Lt, p.Major + 1L, 0, 0, "0")
            : TryAdd(set, Op.Ge, p.Major, p.Minor.Value, 0, null) && TryAdd(set, Op.Lt, p.Major, p.Minor.Value + 1L, 0, "0");

    private static bool AddGreater(Partial p, bool orEqual, List<Comparator> set)
    {
        if (p.IsAny)
        {
            // ">=*" is any version; ">*" is none.
            return orEqual || TryAdd(set, Op.Lt, 0, 0, 0, "0");
        }

        if (p.IsFull)
        {
            return TryAdd(set, orEqual ? Op.Ge : Op.Gt, p.Major, p.Minor!.Value, p.Patch!.Value, p.Prerelease);
        }

        if (orEqual)
        {
            return TryAdd(set, Op.Ge, p.Major, p.Minor ?? 0, 0, null);
        }

        // ">1.2" means at or above 1.3.0; ">1" means at or above 2.0.0.
        return p.Minor is null
            ? TryAdd(set, Op.Ge, p.Major + 1L, 0, 0, null)
            : TryAdd(set, Op.Ge, p.Major, p.Minor.Value + 1L, 0, null);
    }

    private static bool AddLess(Partial p, bool orEqual, List<Comparator> set)
    {
        if (p.IsAny)
        {
            // "<=*" is any version; "<*" is none.
            return orEqual || TryAdd(set, Op.Lt, 0, 0, 0, "0");
        }

        if (p.IsFull)
        {
            return TryAdd(set, orEqual ? Op.Le : Op.Lt, p.Major, p.Minor!.Value, p.Patch!.Value, p.Prerelease);
        }

        if (!orEqual)
        {
            return p.Minor is null
                ? TryAdd(set, Op.Lt, p.Major, 0, 0, "0")
                : TryAdd(set, Op.Lt, p.Major, p.Minor.Value, 0, "0");
        }

        return p.Minor is null
            ? TryAdd(set, Op.Lt, p.Major + 1L, 0, 0, "0")
            : TryAdd(set, Op.Lt, p.Major, p.Minor.Value + 1L, 0, "0");
    }

    private static bool AddTilde(Partial p, List<Comparator> set)
    {
        if (p.IsAny)
        {
            return true;
        }

        if (p.Minor is null)
        {
            return AddRange(p, set);   // ~1 is >=1.0.0 <2.0.0-0
        }

        // ~1.2.3 and ~1.2 are >=1.2.x <1.3.0-0
        return TryAdd(set, Op.Ge, p.Major, p.Minor.Value, p.Patch ?? 0, p.IsFull ? p.Prerelease : null)
            && TryAdd(set, Op.Lt, p.Major, p.Minor.Value + 1L, 0, "0");
    }

    private static bool AddCaret(Partial p, List<Comparator> set)
    {
        if (p.IsAny)
        {
            return true;
        }

        if (p.Minor is null)
        {
            return AddRange(p, set);   // ^1 is >=1.0.0 <2.0.0-0, ^0 is >=0.0.0 <1.0.0-0
        }

        long major = p.Major;
        long minor = p.Minor.Value;
        string? prerelease = p.IsFull ? p.Prerelease : null;

        if (p.Patch is null)
        {
            // ^1.2 is >=1.2.0 <2.0.0-0; ^0.2 is >=0.2.0 <0.3.0-0; ^0.0 is >=0.0.0 <0.1.0-0
            return TryAdd(set, Op.Ge, major, minor, 0, null)
                && (major > 0 ? TryAdd(set, Op.Lt, major + 1L, 0, 0, "0") : TryAdd(set, Op.Lt, 0, minor + 1L, 0, "0"));
        }

        long patch = p.Patch.Value;

        if (!TryAdd(set, Op.Ge, major, minor, patch, prerelease))
        {
            return false;
        }

        if (major > 0)
        {
            return TryAdd(set, Op.Lt, major + 1L, 0, 0, "0");
        }

        return minor > 0
            ? TryAdd(set, Op.Lt, 0, minor + 1L, 0, "0")
            : TryAdd(set, Op.Lt, 0, 0, patch + 1L, "0");
    }

    private static bool TryAdd(List<Comparator> set, Op op, long major, long minor, long patch, string? prerelease)
    {
        string text = $"{major}.{minor}.{patch}" + (prerelease is null ? string.Empty : "-" + prerelease);

        if (!Ecosystem.Npm.TryParseVersion(text, out NuGetVersion? version) || version is null)
        {
            return false;
        }

        set.Add(new Comparator(op, version));
        return true;
    }

    /// <summary>A possibly partial version: Major null-free; Minor and Patch null when missing or a wildcard.</summary>
    private readonly record struct Partial(long Major, long? Minor, long? Patch, string? Prerelease, bool IsAny)
    {
        public bool IsFull => !IsAny && Minor is not null && Patch is not null;
    }

    private static bool TryParsePartial(string text, out Partial partial)
    {
        partial = default;
        Match match = PartialPattern().Match(text);

        if (!match.Success)
        {
            return false;
        }

        string major = match.Groups[1].Value;
        string minor = match.Groups[2].Value;
        string patch = match.Groups[3].Value;
        string prerelease = match.Groups[4].Value;

        if (IsWildcard(major))
        {
            // "*" and "x" stand for every version; "x.2" is not a thing, and neither is a prerelease on a wildcard.
            partial = new Partial(0, null, null, null, IsAny: true);
            return (minor.Length == 0 || IsWildcard(minor)) && (patch.Length == 0 || IsWildcard(patch)) && prerelease.Length == 0;
        }

        if (!long.TryParse(major, out long majorNumber) || majorNumber > int.MaxValue)
        {
            return false;
        }

        long? minorNumber = null;
        long? patchNumber = null;

        if (minor.Length > 0 && !IsWildcard(minor))
        {
            if (!long.TryParse(minor, out long m) || m > int.MaxValue)
            {
                return false;
            }

            minorNumber = m;

            if (patch.Length > 0 && !IsWildcard(patch))
            {
                if (!long.TryParse(patch, out long p) || p > int.MaxValue)
                {
                    return false;
                }

                patchNumber = p;
            }
        }

        // A prerelease needs a complete version.
        if (prerelease.Length > 0 && patchNumber is null)
        {
            return false;
        }

        partial = new Partial(majorNumber, minorNumber, patchNumber, prerelease.Length > 0 ? prerelease : null, IsAny: false);
        return true;
    }

    private static bool IsWildcard(string part) => part is "x" or "X" or "*";

    // v1.2.3-beta.1+build, 1.2, 1.x, *; numbers without leading zeros; the optional "v" prefix is dropped.
    [GeneratedRegex(@"^[vV]?(0|[1-9][0-9]*|[xX*])(?:\.(0|[1-9][0-9]*|[xX*])(?:\.(0|[1-9][0-9]*|[xX*])(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)?)?$")]
    private static partial Regex PartialPattern();

    [GeneratedRegex(@"^(\S+)\s+-\s+(\S+)$")]
    private static partial Regex HyphenPattern();

    [GeneratedRegex(@"(>=|<=|>|<|=|~>|~|\^)\s+")]
    private static partial Regex OperatorSpacePattern();
}
