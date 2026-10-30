using DepRisk.Core;
using DepRisk.Core.Advisories;
using DepRisk.Core.Model;
using DepRisk.Core.Versioning;
using DepRisk.Data.Osv;

namespace DepRisk.Data;

/// <summary>A findings result plus the digest of everything read to produce it, and the loaded snapshot's diagnostics.</summary>
public sealed record FindingsOutcome(FindingsResult Result, string InputsDigest, AdvisorySnapshot Snapshot);

/// <summary>Scans a path for the restored dependency graph and matches every package against local OSV advisories.</summary>
public static class FindingsService
{
    public static FindingsOutcome Match(string scanPath, string advisoriesPath, ToolInfo tool, bool strict)
    {
        ArgumentNullException.ThrowIfNull(scanPath);
        ArgumentNullException.ThrowIfNull(advisoriesPath);
        ArgumentNullException.ThrowIfNull(tool);

        ScanOutcome scan = ScanService.ScanDetailed(scanPath, tool);
        AdvisorySnapshot snapshot = AdvisorySnapshotLoader.Load(advisoriesPath);

        if (strict && snapshot.SkippedInvalid > 0)
        {
            throw new InvalidInputException(
                $"{snapshot.SkippedInvalid} advisory record(s) are invalid and --strict was given. First problem: {snapshot.InvalidSamples[0]}");
        }

        FindingsResult result = Compute(scan.Result, snapshot, tool);
        string inputsDigest = Digest.Sha256Hex(scan.InputsDigest + "\n" + snapshot.Digest + "\n");
        return new FindingsOutcome(result, inputsDigest, snapshot);
    }

    /// <summary>Pure matching of an already-built scan result against a snapshot.</summary>
    public static FindingsResult Compute(ScanResult scan, AdvisorySnapshot snapshot, ToolInfo tool)
    {
        AdvisoryIndex index = AdvisoryIndex.Build(snapshot.Advisories);

        Dictionary<string, Accumulator> findings = new(StringComparer.Ordinal);
        HashSet<string> scanned = new(StringComparer.OrdinalIgnoreCase);
        HashSet<string> skipped = new(StringComparer.OrdinalIgnoreCase);

        foreach (ProjectGraph project in scan.Projects)
        {
            foreach (TargetGraph target in project.Targets)
            {
                foreach (ResolvedPackage package in target.Packages)
                {
                    if (!NuGetVersion.TryParse(package.Version, out NuGetVersion? version) || version is null)
                    {
                        skipped.Add($"{package.Id}@{package.Version}");
                        continue;
                    }

                    string normalized = version.ToString();
                    scanned.Add($"{package.Id}@{normalized}");

                    foreach (AdvisoryMatch match in index.Find(package.Id, version))
                    {
                        string key = $"{match.Advisory.Id}\n{package.Id.ToLowerInvariant()}\n{normalized}";

                        if (!findings.TryGetValue(key, out Accumulator? accumulator))
                        {
                            accumulator = new Accumulator(match, package.Id, normalized);
                            findings[key] = accumulator;
                        }

                        accumulator.Locations.Add(new FindingLocation(project.Name, target.Name, package.IsDirect, project.ProjectFile ?? project.AssetsFile));
                    }
                }
            }
        }

        List<Finding> ordered = findings.Values
            .Select(a => a.ToFinding())
            .OrderBy(f => f.Id, StringComparer.Ordinal)
            .ThenBy(f => f.Package.Id, StringComparer.OrdinalIgnoreCase)
            .ThenBy(f => f.Package.Version, StringComparer.Ordinal)
            .ToList();

        AdvisorySourceInfo source = new(
            snapshot.Source,
            snapshot.Digest,
            snapshot.Advisories.Count,
            snapshot.SkippedWithdrawn,
            snapshot.SkippedNotNuGet,
            snapshot.SkippedInvalid);

        return new FindingsResult(
            FindingsResult.CurrentSchemaVersion,
            tool,
            "nuget",
            source,
            scan.Projects.Count,
            scanned.Count,
            skipped.Count,
            ordered);
    }

    private sealed class Accumulator
    {
        private readonly AdvisoryMatch _match;
        private readonly string _packageId;
        private readonly string _version;

        public Accumulator(AdvisoryMatch match, string packageId, string version)
        {
            _match = match;
            _packageId = packageId;
            _version = version;
        }

        public List<FindingLocation> Locations { get; } = [];

        public Finding ToFinding() =>
            new(
                _match.Advisory.Id,
                _match.Advisory.Aliases,
                _match.Advisory.Summary,
                _match.Advisory.DatabaseSeverity,
                _match.Advisory.Scores,
                new FindingPackage(_packageId, _version),
                _match.FixedVersions.Select(v => v.ToString()).ToList(),
                Locations
                    .Distinct()
                    .OrderBy(l => l.Project, StringComparer.Ordinal)
                    .ThenBy(l => l.Target, StringComparer.Ordinal)
                    .ToList());
    }
}
