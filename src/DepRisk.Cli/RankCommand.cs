using System.Globalization;
using System.Text;
using DepRisk.Audit;
using DepRisk.Core;
using DepRisk.Core.Cvss;
using DepRisk.Core.Model;
using DepRisk.Data;

namespace DepRisk.Cli;

/// <summary>
/// <c>deprisk rank [path] --advisories &lt;...&gt; [--epss file] [--kev file] [--format table|json] [--out file] [--strict]</c>:
/// like <c>match</c>, then orders the findings with the baseline ranking (CISA KEV, then EPSS, then CVSS base score).
/// Offline: EPSS and KEV are local files you supply. This is the reference baseline; it considers neither
/// reachability nor uncertainty yet.
/// </summary>
internal static class RankCommand
{
    private static readonly string[] SupportedFormats = ["table", "json"];

    public static ExitCode Run(string[] args, TextWriter output, CliContext context)
    {
        string path = ".";
        string? advisories = null;
        string? epss = null;
        string? kev = null;
        string format = "table";
        string? outFile = null;
        bool strict = false;
        bool pathSet = false;

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];

            if (arg is "--advisories" or "-a")
            {
                advisories = ReadValue(args, ref i, arg);
            }
            else if (arg.StartsWith("--advisories=", StringComparison.Ordinal))
            {
                advisories = arg["--advisories=".Length..];
            }
            else if (arg == "--epss")
            {
                epss = ReadValue(args, ref i, arg);
            }
            else if (arg.StartsWith("--epss=", StringComparison.Ordinal))
            {
                epss = arg["--epss=".Length..];
            }
            else if (arg == "--kev")
            {
                kev = ReadValue(args, ref i, arg);
            }
            else if (arg.StartsWith("--kev=", StringComparison.Ordinal))
            {
                kev = arg["--kev=".Length..];
            }
            else if (arg is "--format" or "-f")
            {
                format = ReadValue(args, ref i, arg);
            }
            else if (arg.StartsWith("--format=", StringComparison.Ordinal))
            {
                format = arg["--format=".Length..];
            }
            else if (arg is "--out" or "-o")
            {
                outFile = ReadValue(args, ref i, arg);
            }
            else if (arg.StartsWith("--out=", StringComparison.Ordinal))
            {
                outFile = arg["--out=".Length..];
            }
            else if (arg == "--strict")
            {
                strict = true;
            }
            else if (arg.StartsWith('-'))
            {
                throw new InvalidInputException($"unknown option '{arg}' for 'rank'.");
            }
            else if (!pathSet)
            {
                path = arg;
                pathSet = true;
            }
            else
            {
                throw new InvalidInputException("'rank' takes at most one path.");
            }
        }

        if (!SupportedFormats.Contains(format, StringComparer.Ordinal))
        {
            throw new InvalidInputException(
                $"format '{format}' is not supported for 'rank' (supported: {string.Join(", ", SupportedFormats)}).");
        }

        if (advisories is null)
        {
            throw new InvalidInputException(
                "'rank' needs advisory data: pass --advisories <directory | .zip | .json> (OSV format). "
                + "Optionally add --epss <epss_scores-*.csv[.gz]> (FIRST EPSS) and --kev <known_exploited_vulnerabilities.json> (CISA KEV). "
                + "See docs/adr/0006-advisory-data-and-matching.md and docs/adr/0007-baseline-ranking.md.");
        }

        RankingOutcome outcome = RankingService.Rank(
            Path.GetFullPath(path, context.WorkingDirectory),
            Path.GetFullPath(advisories, context.WorkingDirectory),
            epss is null ? null : Path.GetFullPath(epss, context.WorkingDirectory),
            kev is null ? null : Path.GetFullPath(kev, context.WorkingDirectory),
            new ToolInfo(ProductInfo.CommandName, VersionInfo.Current),
            strict);

        string json = RankingResultJson.Serialize(outcome.Result);
        string text = format == "json" ? json : RenderTable(outcome);

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

        AuditRecorder.RecordIfEnabled(
            context,
            new AuditDraft("rank", ArgRedactor.Redact(args), outcome.InputsDigest, Digest.Sha256Hex(json), changes));

        if (outFile is null)
        {
            output.Write(text);
        }
        else
        {
            output.Write($"Wrote {format} ranking to {outFile} ({outcome.Result.Findings.Count} finding(s))\n");
        }

        return ExitCode.Success;
    }

    private static string ReadValue(string[] args, ref int index, string option)
    {
        if (index + 1 >= args.Length)
        {
            throw new InvalidInputException($"option '{option}' needs a value.");
        }

        index++;
        return args[index];
    }

    private static string RenderTable(RankingOutcome outcome)
    {
        RankingResult result = outcome.Result;
        AdvisorySourceInfo source = result.Advisories;
        StringBuilder text = new();

        text.Append($"deprisk rank: {result.ProjectsScanned} project(s), {result.PackagesScanned} package version(s) scanned\n");
        text.Append($"advisories: {TerminalText.Safe(source.Source, 80)}  {source.Count} NuGet advisories, sha256 {source.Digest[..12]}\n");
        text.Append(DescribeSignal("EPSS", result.Signals.Epss, "model", "score date", "CVEs"));
        text.Append(DescribeSignal("KEV", result.Signals.Kev, "catalog", "released", "entries"));
        text.Append("method: baseline: in CISA KEV first, then EPSS probability, then CVSS base score, then database severity, then id.\n");
        text.Append("        No reachability and no uncertainty yet; this is the reference the later model is compared with.\n");

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
        }

        text.Append("\nMatching is by package version only: reachability of the vulnerable code is not considered yet.\n");
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
