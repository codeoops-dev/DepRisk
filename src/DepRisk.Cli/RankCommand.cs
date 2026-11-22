using System.Globalization;
using System.Text;
using DepRisk.Audit;
using DepRisk.Core;
using DepRisk.Core.Cvss;
using DepRisk.Core.Model;
using DepRisk.Core.Risk;
using DepRisk.Core.Policy;
using DepRisk.Data;
using DepRisk.Data.Risk;
using DepRisk.Data.Reach;
using DepRisk.Data.Sarif;

namespace DepRisk.Cli;

/// <summary>
/// <c>deprisk rank [path] [--ecosystem auto|nuget|npm] --advisories &lt;...&gt; [--epss file] [--kev file] [--format table|json|sarif] [--out file] [--strict]</c>:
/// like <c>match</c>, then orders the findings with the baseline ranking (CISA KEV, then EPSS, then CVSS base score).
/// Offline: EPSS and KEV are local files you supply. This is the reference baseline; it considers neither
/// reachability nor uncertainty yet.
/// <c>deprisk ci</c> is the same analysis plus a policy gate (<c>--fail-on</c>): exit code 1 when a finding trips it.
/// </summary>
internal static class RankCommand
{
    private static readonly string[] SupportedFormats = ["table", "json", "sarif"];

    public static ExitCode Run(string[] args, TextWriter output, CliContext context) =>
        Run(args, output, TextWriter.Null, context, "rank", ci: false);

    public static ExitCode Run(string[] args, TextWriter output, TextWriter error, CliContext context, string commandName, bool ci)
    {
        string path = ".";
        string? failOn = null;
        string format = "table";
        string? outFile = null;
        bool pathSet = false;
        AnalysisArgs analysis = new();

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];

            if (analysis.TryRead(args, ref i, arg, commandName))
            {
                continue;
            }

            if (OptionValue.TryValue(args, ref i, arg, "--format", "-f", out string? value))
            {
                format = value!;
            }
            else if (OptionValue.TryValue(args, ref i, arg, "--out", "-o", out value))
            {
                outFile = value;
            }
            else if (ci && OptionValue.TryValue(args, ref i, arg, "--fail-on", null, out value))
            {
                failOn = value;
            }
            else if (arg.StartsWith('-'))
            {
                throw new InvalidInputException($"unknown option '{arg}' for '{commandName}'.");
            }
            else if (!pathSet)
            {
                path = arg;
                pathSet = true;
            }
            else
            {
                throw new InvalidInputException($"'{commandName}' takes at most one path.");
            }
        }

        if (!SupportedFormats.Contains(format, StringComparer.Ordinal))
        {
            throw new InvalidInputException(
                $"format '{format}' is not supported for '{commandName}' (supported: {string.Join(", ", SupportedFormats)}).");
        }

        analysis.RequireAdvisories(
            commandName,
            $"'{commandName}' needs advisory data: pass --advisories <directory | .zip | .json> (OSV format). "
            + "Optionally add --epss <epss_scores-*.csv[.gz]> (FIRST EPSS) and --kev <known_exploited_vulnerabilities.json> (CISA KEV). "
            + "See docs/adr/0006-advisory-data-and-matching.md and docs/adr/0007-baseline-ranking.md.");

        PolicyExpression? policy = null;

        if (failOn is not null)
        {
            if (!PolicyExpression.TryParse(failOn, out policy, out string policyError))
            {
                throw new InvalidInputException($"--fail-on: {policyError}");
            }
        }

        string scanPath = Path.GetFullPath(path, context.WorkingDirectory);

        // Checks the reachability and risk options and loads the risk parameters (in that order), then builds the pipeline options.
        RankPipelineOptions pipelineOptions = analysis.ToPipelineOptions(commandName, scanPath, context);

        if (policy is { UsesReachability: true } && analysis.Reach.Symbols is null)
        {
            throw new InvalidInputException(
                "--fail-on uses reachability terms (reachable, possibly-reachable, reach-unknown, unreachable, not-unreachable), "
                + "which need --symbols (and the analyzer): without a verdict they would silently match nothing.");
        }

        RankPipelineOutcome pipeline = RankPipeline.Run(
            pipelineOptions,
            new ToolInfo(ProductInfo.CommandName, VersionInfo.Current),
            new AnalyzerProcess(),
            Environment.GetEnvironmentVariable,
            AppContext.BaseDirectory);

        RankingOutcome outcome = pipeline.Ranking;

        string json = RankingResultJson.Serialize(outcome.Result);
        string text = format switch
        {
            "json" => json,
            "sarif" => SarifWriter.Serialize(outcome.Result),
            _ => RenderTable(outcome),
        };

        IReadOnlyList<RankedFinding> tripped = policy is null ? [] : policy.Evaluate(outcome.Result.Findings);

        List<AuditChange> changes = [];

        if (outFile is not null)
        {
            string outPath = Path.GetFullPath(outFile, context.WorkingDirectory);
            bool existed = File.Exists(outPath);

            try
            {
                File.WriteAllText(outPath, text, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new InvalidInputException($"cannot write '{outFile}' ({ex.Message})", ex);
            }

            changes.Add(new AuditChange(outFile.Replace('\\', '/'), existed ? "existing file" : null, "written"));
        }

        if (policy is not null)
        {
            // The decision is part of the record: expression -> result.
            changes.Add(new AuditChange("policy gate", policy.Text, tripped.Count == 0 ? "passed" : $"failed ({tripped.Count} finding(s))"));
        }

        AuditRecorder.RecordIfEnabled(
            context,
            new AuditDraft(commandName, ArgRedactor.Redact(args), outcome.InputsDigest, Digest.Sha256Hex(json), changes));

        if (outFile is null)
        {
            output.Write(text);
        }
        else
        {
            output.Write($"Wrote {format} ranking to {outFile} ({outcome.Result.Findings.Count} finding(s))\n");
        }

        return ci ? ReportGate(error, policy, outcome.Result.Findings.Count, tripped) : ExitCode.Success;
    }

    /// <summary>The verdict goes to the error stream so that json and sarif on standard output stay clean.</summary>
    private static ExitCode ReportGate(TextWriter error, PolicyExpression? policy, int total, IReadOnlyList<RankedFinding> tripped)
    {
        if (policy is null)
        {
            error.Write($"{ProductInfo.CommandName}: ci: no policy set (--fail-on), so the gate was not evaluated. {total} finding(s) reported.\n");
            return ExitCode.Success;
        }

        string expression = TerminalText.Safe(policy.Text, 200);

        if (tripped.Count == 0)
        {
            error.Write($"{ProductInfo.CommandName}: ci: policy gate PASSED ('{expression}'): none of {total} finding(s) match.\n");
            return ExitCode.Success;
        }

        error.Write($"{ProductInfo.CommandName}: ci: policy gate FAILED ('{expression}'): {tripped.Count} of {total} finding(s) match:\n");

        foreach (RankedFinding finding in tripped.Take(10))
        {
            string reachText = finding.Reachability is null ? string.Empty : $"  [reach: {finding.Reachability.Label}]";
            error.Write($"  #{finding.Rank} {TerminalText.Safe(finding.Id, 60)}  {TerminalText.Safe(finding.Package.Id, 80)} {finding.Package.Version}{reachText}\n");
        }

        if (tripped.Count > 10)
        {
            error.Write($"  ... and {tripped.Count - 10} more\n");
        }

        return ExitCode.PolicyGateFailed;
    }

    internal static string RenderTable(RankingOutcome outcome)
    {
        RankingResult result = outcome.Result;
        AdvisorySourceInfo source = result.Advisories;
        StringBuilder text = new();

        text.Append($"deprisk rank: {result.ProjectsScanned} project(s), {result.PackagesScanned} package version(s) scanned\n");
        text.Append($"advisories: {TerminalText.Safe(source.Source, 80)}  {source.Count} {Ecosystem.FromId(result.Ecosystem).DisplayName} advisories, sha256 {source.Digest[..12]}\n");
        text.Append(DescribeSignal("EPSS", result.Signals.Epss, "model", "score date", "CVEs"));
        text.Append(DescribeSignal("KEV", result.Signals.Kev, "catalog", "released", "entries"));
        if (result.Model is { } riskModel)
        {
            text.Append($"method: risk model: R = Reach x Exploit x Impact over {riskModel.Samples} seeded scenarios, ranked by {riskModel.RankBy} (seed {riskModel.Seed}, {riskModel.SeedSource}).\n");
            text.Append($"        Parameters: {riskModel.Calibration} (digest {riskModel.ParametersDigest[..12]}). The numbers order findings by modeled risk; they are not probabilities of real-world loss.\n");
        }
        else
        {
            text.Append("method: baseline: in CISA KEV first, then EPSS probability, then CVSS base score, then database severity, then id.\n");
        }

        if (result.Reach is { } reachInfo)
        {
            text.Append(result.Model is null
                ? "        Reachability is shown for each finding and can be used in --fail-on; it does not change the order.\n"
                : "        Reachability is an input of the risk model and can also be used in --fail-on.\n");
            text.Append($"reachability: symbol maps {TerminalText.Safe(reachInfo.SymbolMaps.Source, 80)} ({reachInfo.SymbolMaps.Entries} entr{(reachInfo.SymbolMaps.Entries == 1 ? "y" : "ies")}, sha256 {reachInfo.SymbolMaps.Digest[..12]}); ");
            text.Append(reachInfo.Analyzer is null ? "analyzer not run" : $"analyzer {TerminalText.Safe(reachInfo.Analyzer.Name, 40)} {TerminalText.Safe(reachInfo.Analyzer.Version, 40)} sha256 {reachInfo.Analyzer.Sha256[..12]}");
            text.Append($"; {reachInfo.Summary.Reachable} reachable, {reachInfo.Summary.PossiblyReachable} possibly reachable, {reachInfo.Summary.Unknown} unknown, {reachInfo.Summary.Unreachable} unreachable\n");
        }
        else
        {
            text.Append("        No reachability and no uncertainty yet; this is the reference the later model is compared with (add --symbols for reachability).\n");
        }

        if (source.SkippedInvalid > 0)
        {
            text.Append($"WARNING: {source.SkippedInvalid} advisory record(s) could not be read, so vulnerabilities may be missing. First: {TerminalText.Safe(outcome.Findings.Snapshot.InvalidSamples[0], 160)}\n");
        }

        if (outcome.Epss is { SkippedRows: > 0 })
        {
            text.Append($"WARNING: {outcome.Epss.SkippedRows} EPSS row(s) were malformed and ignored. First: {TerminalText.Safe(outcome.Epss.SkippedSamples[0], 120)}\n");
        }

        if (outcome.Kev is { SkippedEntries: > 0 })
        {
            text.Append($"WARNING: {outcome.Kev.SkippedEntries} KEV entr(ies) were malformed and ignored. First: {TerminalText.Safe(outcome.Kev.SkippedSamples[0], 120)}\n");
        }

        text.Append($"findings: {result.Findings.Count}\n");

        if (result.Findings.Count == 0)
        {
            text.Append("\nNo known vulnerabilities found. This is only as complete as the advisory data you supplied.\n");
            return text.ToString();
        }

        foreach (RankedFinding finding in result.Findings)
        {
            FindingSignals signals = finding.Signals;
            string kevText = signals.Kev is null ? "-" : signals.Kev.KnownRansomwareUse ? "KEV+ransomware" : "KEV";
            string epssText = signals.Epss is null
                ? "-"
                : $"EPSS {signals.Epss.Probability.ToString("0.000", CultureInfo.InvariantCulture)}";
            string cvssText = signals.Cvss is null
                ? $"CVSS - ({TerminalText.Safe(finding.Severity ?? "no rating", 10).ToUpperInvariant()})"
                : $"CVSS {CvssV3.Format(signals.Cvss.BaseScore)} {signals.Cvss.Rating}";
            string direct = finding.Locations.Any(l => l.IsDirect) ? "direct" : "transitive";
            string fix = finding.FixedVersions.Count == 0 ? "no fixed version known" : "fixed in " + string.Join(", ", finding.FixedVersions);

            text.Append('\n');
            text.Append($"{finding.Rank,4}  {kevText,-14} {epssText,-11} {cvssText,-18} {TerminalText.Safe(finding.Id, 60)}  {TerminalText.Safe(finding.Package.Id, 80)} {finding.Package.Version} ({direct}); {fix}\n");

            if (finding.Summary is not null)
            {
                text.Append($"      {TerminalText.Safe(finding.Summary, 140)}\n");
            }

            if (finding.Risk is { } risk)
            {
                string c(double v) => v.ToString("0.00", System.Globalization.CultureInfo.InvariantCulture);
                text.Append($"      risk: mean {c(risk.Mean)}  p50 {c(risk.P50)}  p95 {c(risk.P95)}  cvar95 {c(risk.Cvar95)}   (reach {c(risk.ReachMean)}, exploit {c(risk.ExploitMean)}, impact {c(risk.ImpactMean)})  baseline #{finding.BaselineRank}\n");
            }

            if (finding.Reachability is { } reachVerdict)
            {
                string via = reachVerdict.Symbol is null ? string.Empty : $"; via {TerminalText.Safe(reachVerdict.Symbol, 100)}";
                text.Append($"      reachability: {reachVerdict.Label} ({ReachCommand.Describe(reachVerdict.Reason)}{via})\n");
            }
        }

        text.Append(result.Reach is null
            ? "\nMatching is by package version only: reachability of the vulnerable code is not considered (add --symbols).\n"
            : "\nMatching is by package version; reachability labels describe a conservative call graph, not exploitability (see 'deprisk reach' for the paths).\n");
        return text.ToString();
    }

    private static string DescribeSignal(string name, SignalSourceInfo? info, string versionLabel, string dateLabel, string countLabel)
    {
        if (info is null)
        {
            return $"{name}: not supplied (ordering skips this signal)\n";
        }

        List<string> parts = [];

        if (info.Version is not null)
        {
            parts.Add($"{versionLabel} {TerminalText.Safe(info.Version, 40)}");
        }

        if (info.Date is not null)
        {
            parts.Add($"{dateLabel} {TerminalText.Safe(info.Date, 40)}");
        }

        parts.Add($"{info.Entries} {countLabel}");
        parts.Add($"sha256 {info.Digest[..12]}");
        return $"{name}: {TerminalText.Safe(info.Source, 80)}  ({string.Join(", ", parts)})\n";
    }
}
