using DepRisk.Core.Versioning;

namespace DepRisk.Core.Advisories;

/// <summary>An advisory that applies to a package version, with the versions that fix it (above the installed one).</summary>
public sealed record AdvisoryMatch(Advisory Advisory, IReadOnlyList<NuGetVersion> FixedVersions);

/// <summary>
/// Looks up advisories by package id (case-insensitive) and decides whether a version is affected.
/// Range evaluation follows the OSV schema: events are processed in ascending version order; "introduced"
/// switches the state to affected for versions at or above it ("0" means from the beginning), "fixed"
/// switches it off at or above, "last_affected" switches it off above. A version is also affected if it
/// appears in the explicit "versions" list.
/// </summary>
public sealed class AdvisoryIndex
{
    private readonly Dictionary<string, List<Entry>> _byPackage = new(StringComparer.OrdinalIgnoreCase);

    private AdvisoryIndex(Ecosystem ecosystem) => Ecosystem = ecosystem;

    /// <summary>The ecosystem this index answers for: only its entries are indexed, and its version rules apply.</summary>
    public Ecosystem Ecosystem { get; }

    public int AdvisoryCount { get; private set; }

    /// <summary>Builds an index for NuGet (kept for callers that predate multiple ecosystems).</summary>
    public static AdvisoryIndex Build(IEnumerable<Advisory> advisories) => Build(advisories, Ecosystem.NuGet);

    public static AdvisoryIndex Build(IEnumerable<Advisory> advisories, Ecosystem ecosystem)
    {
        ArgumentNullException.ThrowIfNull(advisories);
        ArgumentNullException.ThrowIfNull(ecosystem);

        AdvisoryIndex index = new(ecosystem);

        foreach (Advisory advisory in advisories)
        {
            if (advisory.Withdrawn)
            {
                continue;
            }

            bool any = false;

            foreach (AffectedPackage affected in advisory.Affected)
            {
                if (!string.Equals(affected.Ecosystem, ecosystem.OsvName, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!index._byPackage.TryGetValue(affected.Name, out List<Entry>? entries))
                {
                    entries = [];
                    index._byPackage[affected.Name] = entries;
                }

                entries.Add(new Entry(advisory, Compile(affected, ecosystem)));
                any = true;
            }

            if (any)
            {
                index.AdvisoryCount++;
            }
        }

        return index;
    }

    /// <summary>All advisories that affect <paramref name="packageId"/> at <paramref name="version"/>, one match per advisory.</summary>
    public IReadOnlyList<AdvisoryMatch> Find(string packageId, NuGetVersion version)
    {
        ArgumentNullException.ThrowIfNull(packageId);
        ArgumentNullException.ThrowIfNull(version);

        if (!_byPackage.TryGetValue(packageId, out List<Entry>? entries))
        {
            return [];
        }

        Dictionary<string, (Advisory Advisory, SortedSet<NuGetVersion> Fixed)> matches = new(StringComparer.Ordinal);

        foreach (Entry entry in entries)
        {
            if (!entry.Package.IsAffected(version, out List<NuGetVersion> fixedVersions))
            {
                continue;
            }

            if (!matches.TryGetValue(entry.Advisory.Id, out var found))
            {
                found = (entry.Advisory, []);
                matches[entry.Advisory.Id] = found;
            }

            foreach (NuGetVersion fixedVersion in fixedVersions)
            {
                found.Fixed.Add(fixedVersion);
            }
        }

        return matches.Values
            .OrderBy(m => m.Advisory.Id, StringComparer.Ordinal)
            .Select(m => new AdvisoryMatch(m.Advisory, m.Fixed.ToList()))
            .ToList();
    }

    private static CompiledPackage Compile(AffectedPackage affected, Ecosystem ecosystem)
    {
        List<CompiledRange> ranges = [];

        foreach (AffectedRange range in affected.Ranges)
        {
            if (!range.Type.Equals("ECOSYSTEM", StringComparison.OrdinalIgnoreCase)
                && !range.Type.Equals("SEMVER", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            List<CompiledEvent> events = [];

            foreach (RangeEvent rangeEvent in range.Events)
            {
                CompiledEvent? compiled = CompiledEvent.TryCreate(rangeEvent, ecosystem);

                if (compiled is not null)
                {
                    events.Add(compiled);
                }
            }

            // Ascending by version; at equal versions: introduced, then fixed, then last_affected.
            events = events
                .OrderBy(e => e, CompiledEvent.Order)
                .ToList();

            ranges.Add(new CompiledRange(events));
        }

        return new CompiledPackage(ranges, affected.Versions, ecosystem);
    }

    private sealed record Entry(Advisory Advisory, CompiledPackage Package);

    private sealed class CompiledPackage
    {
        private readonly List<CompiledRange> _ranges;
        private readonly IReadOnlyList<string> _versions;
        private readonly Ecosystem _ecosystem;

        public CompiledPackage(List<CompiledRange> ranges, IReadOnlyList<string> versions, Ecosystem ecosystem)
        {
            _ranges = ranges;
            _versions = versions;
            _ecosystem = ecosystem;
        }

        public bool IsAffected(NuGetVersion version, out List<NuGetVersion> fixedVersions)
        {
            fixedVersions = [];
            bool affected = false;

            foreach (CompiledRange range in _ranges)
            {
                if (range.Contains(version))
                {
                    affected = true;
                    fixedVersions.AddRange(range.FixedAbove(version));
                }
            }

            if (!affected && _versions.Any(v => ListedVersionEquals(v, version, _ecosystem)))
            {
                affected = true;
            }

            return affected;
        }

        private static bool ListedVersionEquals(string listed, NuGetVersion version, Ecosystem ecosystem) =>
            ecosystem.TryParseVersion(listed, out NuGetVersion? parsed) && parsed is not null
                ? parsed.Equals(version)
                : string.Equals(listed, version.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    private sealed class CompiledRange
    {
        private readonly List<CompiledEvent> _events;

        public CompiledRange(List<CompiledEvent> events) => _events = events;

        public bool Contains(NuGetVersion version)
        {
            bool affected = false;

            foreach (CompiledEvent e in _events)
            {
                switch (e.Kind)
                {
                    case "introduced":
                        if (e.IsBeginning || version.CompareTo(e.Version) >= 0)
                        {
                            affected = true;
                        }

                        break;
                    case "fixed":
                        if (version.CompareTo(e.Version) >= 0)
                        {
                            affected = false;
                        }

                        break;
                    case "last_affected":
                        if (version.CompareTo(e.Version) > 0)
                        {
                            affected = false;
                        }

                        break;
                }
            }

            return affected;
        }

        public IEnumerable<NuGetVersion> FixedAbove(NuGetVersion version) =>
            _events
                .Where(e => e.Kind == "fixed" && e.Version is not null && e.Version.CompareTo(version) > 0)
                .Select(e => e.Version!);
    }

    private sealed class CompiledEvent
    {
        public static readonly IComparer<CompiledEvent> Order = Comparer<CompiledEvent>.Create(Compare);

        private CompiledEvent(string kind, NuGetVersion? version, bool isBeginning)
        {
            Kind = kind;
            Version = version;
            IsBeginning = isBeginning;
        }

        public string Kind { get; }

        /// <summary>Null only for "introduced": "0", which stands for "from the very first version".</summary>
        public NuGetVersion? Version { get; }

        public bool IsBeginning { get; }

        public static CompiledEvent? TryCreate(RangeEvent rangeEvent, Ecosystem ecosystem)
        {
            string kind = rangeEvent.Kind;

            if (kind is not ("introduced" or "fixed" or "last_affected"))
            {
                return null;
            }

            if (kind == "introduced" && rangeEvent.Version == "0")
            {
                return new CompiledEvent(kind, null, isBeginning: true);
            }

            return ecosystem.TryParseVersion(rangeEvent.Version, out NuGetVersion? parsed) && parsed is not null
                ? new CompiledEvent(kind, parsed, isBeginning: false)
                : null;
        }

        private static int Compare(CompiledEvent? a, CompiledEvent? b)
        {
            if (a is null || b is null)
            {
                return 0;
            }

            if (a.IsBeginning != b.IsBeginning)
            {
                return a.IsBeginning ? -1 : 1;
            }

            if (!a.IsBeginning)
            {
                int byVersion = a.Version!.CompareTo(b.Version!);

                if (byVersion != 0)
                {
                    return byVersion;
                }
            }

            return Rank(a.Kind).CompareTo(Rank(b.Kind));
        }

        private static int Rank(string kind) => kind switch
        {
            "introduced" => 0,
            "fixed" => 1,
            _ => 2,
        };
    }
}
