using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Core.Reach;

namespace DepRisk.Data.Reach;

public sealed record ReachOptions(
    string ScanPath,
    string AdvisoriesPath,
    string SymbolsPath,
    string? SourceRoot,
    Ecosystem? Ecosystem,
    bool Strict,
    string EntrypointMode,
    IReadOnlyList<string> ExplicitEntrypoints,
    string? AnalyzerPath,
    TimeSpan Timeout,
    string WorkingDirectory);

public sealed record ReachOutcome(ReachabilityResult Result, string InputsDigest, FindingsOutcome Findings);

/// <summary>
/// <c>deprisk reach</c>: finds the advisories that apply (as <c>match</c> does), looks up the symbols through which each is reached,
/// asks the analyzer whether those symbols can be reached from the application's entrypoints, and combines the answers. See
/// ADR 0013. Rules that matter: a finding without symbols is "unknown", never "unreachable"; a package that is only a transitive
/// dependency can be "reachable" if the application calls it directly, but its own code is not analyzed, so "unreachable" becomes
/// "unknown"; an ecosystem without an analyzer is "unknown".
/// </summary>
public static class ReachService
{
    public static ReachOutcome Run(ReachOptions options, ToolInfo tool, IAnalyzerProcess process, Func<string, string?> getEnvironmentVariable, string baseDirectory)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(process);

        FindingsOutcome matched = FindingsService.Match(options.ScanPath, options.AdvisoriesPath, tool, options.Strict, options.Ecosystem);
        LoadedSymbolMaps maps = SymbolMapLoader.Load(options.SymbolsPath);
        FindingsResult findings = matched.Result;
        bool analyzable = findings.Ecosystem == Ecosystem.NuGet.Id;

        // One question per advisory and package, whatever the versions.
        Dictionary<string, SymbolSet> setsByKey = new(StringComparer.Ordinal);
        List<(Finding Finding, string Key, SymbolSet? Set)> items = [];

        foreach (Finding finding in findings.Findings)
        {
            SymbolSet? set = maps.Map.Find([finding.Id, .. finding.Aliases], finding.Package.Id);
            string key = $"{finding.Id}|{finding.Package.Id}";

            if (set is not null)
            {
                setsByKey[key] = set;
            }

            items.Add((finding, key, set));
        }

        List<ReachTarget> targets = analyzable
            ? setsByKey.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => new ReachTarget(p.Key, p.Value.Symbols, p.Value.Complete)).ToList()
            : [];

        ReachAnalyzerInfo? analyzerInfo = null;
        AnalyzerOutput? output = null;
        string analyzerSha = "none";

        if (targets.Count > 0)
        {
            string? executable = AnalyzerLocator.Find(options.AnalyzerPath, options.WorkingDirectory, getEnvironmentVariable, baseDirectory)
                ?? throw new InvalidInputException(AnalyzerLocator.NotFoundMessage());

            string root = ResolveSourceRoot(options);
            analyzerSha = Digest.Sha256Hex(File.ReadAllBytes(executable));
            string request = ReachProtocol.BuildRequest(root, options.EntrypointMode, options.ExplicitEntrypoints, targets);

            AnalyzerRun run = process.Run(executable, request, options.Timeout);

            if (run.ExitCode != 0)
            {
                string firstLine = run.StdErr.Split('\n', 2)[0];
                throw new AnalyzerException($"the analyzer failed (exit code {run.ExitCode}): {SafeText.Clean(firstLine, 200)}");
            }

            output = ReachProtocol.ParseResult(run.StdOut, targets.Select(t => t.Key).ToList());
            analyzerInfo = new ReachAnalyzerInfo(output.AnalyzerName, output.AnalyzerVersion, analyzerSha);
        }

        List<ReachFinding> reached = [];

        foreach ((Finding finding, string key, SymbolSet? set) in items)
        {
            reached.Add(new ReachFinding(finding, Verdict(finding, key, set, analyzable, output)));
        }

        reached = reached
            .Select((r, i) => (r, i))
            .OrderBy(x => ReachLabels.Priority(x.r.Reachability.Label))
            .ThenBy(x => x.i)
            .Select(x => x.r)
            .ToList();

        List<string> diagnostics = [];

        if (output is not null)
        {
            if (output.Source.FilesWithErrors + output.Source.FilesSkipped > 0)
            {
                diagnostics.Add(
                    $"{output.Source.FilesWithErrors} file(s) could not be read completely and {output.Source.FilesSkipped} file(s) were skipped: "
                    + "where no path was found, the verdict is 'unknown', not 'unreachable'.");
            }

            diagnostics.AddRange(output.Diagnostics.Select(d => SafeText.Clean(d, 200)));
        }

        ReachSummary summary = new(
            reached.Count(r => r.Reachability.Label == ReachLabels.Reachable),
            reached.Count(r => r.Reachability.Label == ReachLabels.PossiblyReachable),
            reached.Count(r => r.Reachability.Label == ReachLabels.Unreachable),
            reached.Count(r => r.Reachability.Label == ReachLabels.Unknown));

        ReachabilityResult result = new(
            ReachabilityResult.CurrentSchemaVersion,
            tool,
            findings.Ecosystem,
            findings.Advisories,
            maps.Info,
            analyzerInfo,
            output?.Source,
            summary,
            reached,
            diagnostics);

        string inputs = Digest.Sha256Hex(
            $"findings:{matched.InputsDigest}\nsymbols:{maps.Info.Digest}\nentrypoints:{options.EntrypointMode}|{string.Join(',', options.ExplicitEntrypoints.OrderBy(e => e, StringComparer.Ordinal))}\n"
            + $"analyzer:{analyzerSha}\nsource:{output?.SourceDigest ?? "none"}\n");

        return new ReachOutcome(result, inputs, matched);
    }

    private static string ResolveSourceRoot(ReachOptions options)
    {
        string root = options.SourceRoot is not null
            ? Path.GetFullPath(options.SourceRoot, options.WorkingDirectory)
            : (Directory.Exists(options.ScanPath) ? options.ScanPath : Path.GetDirectoryName(options.ScanPath) ?? options.ScanPath);

        if (!Directory.Exists(root))
        {
            throw new InvalidInputException($"source directory not found: {SafeText.Clean(root, 200)}");
        }

        return root;
    }

    private static ReachVerdict Verdict(Finding finding, string key, SymbolSet? set, bool analyzable, AnalyzerOutput? output)
    {
        if (!analyzable)
        {
            return new ReachVerdict(ReachLabels.Unknown, ReachLabels.NoAnalyzerForEcosystem, null, [], set?.Sources ?? []);
        }

        if (set is null || output is null)
        {
            return new ReachVerdict(ReachLabels.Unknown, ReachLabels.NoSymbols, null, [], []);
        }

        AnalyzerVerdict analyzed = output.Verdicts[key];

        // The package's own code is not analyzed. A path from the application into it is real evidence; the absence of one is not,
        // because the package may be reached through the code of the packages that use it.
        if (analyzed.Label == ReachLabels.Unreachable && finding.Locations.All(l => !l.IsDirect))
        {
            return new ReachVerdict(ReachLabels.Unknown, ReachLabels.TransitivePackage, null, [], set.Sources);
        }

        return new ReachVerdict(analyzed.Label, analyzed.Reason, analyzed.Symbol, analyzed.Path, set.Sources);
    }
}

/// <summary>Canonical JSON for <see cref="ReachabilityResult"/>.</summary>
public static class ReachabilityResultJson
{
    public static string Serialize(ReachabilityResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return System.Text.Json.JsonSerializer.Serialize(result, OutputJson.Options) + "\n";
    }
}
