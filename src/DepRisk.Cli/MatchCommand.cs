using System.Text;
using DepRisk.Audit;
using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Data;

namespace DepRisk.Cli;

/// <summary>
/// <c>deprisk match [path] --advisories &lt;dir|.zip|.json&gt; [--format table|json] [--out file] [--strict]</c>:
/// scans the restored dependency graph and reports which package versions are affected by known advisories.
/// Offline: the advisory data is a local file you supply. Matching is by version only; reachability is not considered yet.
/// </summary>
internal static class MatchCommand
{
    private static readonly string[] SupportedFormats = ["table", "json"];

    public static ExitCode Run(string[] args, TextWriter output, CliContext context)
    {
        string path = ".";
        string? advisories = null;
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
                throw new InvalidInputException($"unknown option '{arg}' for 'match'.");
            }
            else if (!pathSet)
            {
                path = arg;
                pathSet = true;
            }
            else
            {
                throw new InvalidInputException("'match' takes at most one path.");
            }
        }

        if (!SupportedFormats.Contains(format, StringComparer.Ordinal))
        {
            throw new InvalidInputException(
                $"format '{format}' is not supported for 'match' (supported: {string.Join(", ", SupportedFormats)}).");
        }

        if (advisories is null)
        {
            throw new InvalidInputException(
                "'match' needs advisory data: pass --advisories <directory | .zip | .json> (OSV format). "
                + "On a connected machine you can download OSV's NuGet dump (https://osv-vulnerabilities.storage.googleapis.com/NuGet/all.zip) "
                + "and copy it over; see docs/adr/0006-advisory-data-and-matching.md.");
        }

        string scanPath = Path.GetFullPath(path, context.WorkingDirectory);
        string advisoriesPath = Path.GetFullPath(advisories, context.WorkingDirectory);

        FindingsOutcome outcome = FindingsService.Match(
            scanPath,
            advisoriesPath,
            new ToolInfo(ProductInfo.CommandName, VersionInfo.Current),
            strict);

        string json = FindingsResultJson.Serialize(outcome.Result);
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
            new AuditDraft("match", ArgRedactor.Redact(args), outcome.InputsDigest, Digest.Sha256Hex(json), changes));

        if (outFile is null)
        {
            output.Write(text);
        }
        else
        {
            output.Write($"Wrote {format} findings to {outFile} ({outcome.Result.Findings.Count} finding(s))\n");
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

    private static string RenderTable(FindingsOutcome outcome)
    {
        FindingsResult result = outcome.Result;
        AdvisorySourceInfo source = result.Advisories;
        StringBuilder text = new();

        text.Append($"deprisk match: {result.ProjectsScanned} project(s), {result.PackagesScanned} package version(s) scanned\n");
        text.Append($"advisories: {TerminalText.Safe(source.Source, 80)}  {source.Count} NuGet advisories, sha256 {source.Digest[..12]}\n");
        text.Append($"skipped: {source.SkippedWithdrawn} withdrawn, {source.SkippedNotNuGet} not for NuGet, {source.SkippedInvalid} invalid");

        if (result.PackagesSkipped > 0)
        {
            text.Append($"; {result.PackagesSkipped} package(s) with unparsable versions");
        }

        text.Append('\n');

        if (source.SkippedInvalid > 0)
        {
            text.Append($"WARNING: {source.SkippedInvalid} advisory record(s) could not be read, so vulnerabilities may be missing. First: {TerminalText.Safe(outcome.Snapshot.InvalidSamples[0], 160)}\n");
            text.Append("         Use --strict to treat this as an error.\n");
        }

        text.Append($"findings: {result.Findings.Count}\n");

        if (result.Findings.Count == 0)
        {
            text.Append("\nNo known vulnerabilities found. This is only as complete as the advisory data you supplied.\n");
            return text.ToString();
        }

        foreach (Finding finding in result.Findings.OrderByDescending(f => SeverityRank(f.Severity)).ThenBy(f => f.Id, StringComparer.Ordinal).ThenBy(f => f.Package.Id, StringComparer.OrdinalIgnoreCase))
        {
            string severity = TerminalText.Safe(finding.Severity ?? "UNKNOWN", 10).ToUpperInvariant();
            string direct = finding.Locations.Any(l => l.IsDirect) ? "direct" : "transitive";
            string projects = finding.Locations.Select(l => l.Project).Distinct(StringComparer.Ordinal).Count() is var n and > 1 ? $", {n} projects" : string.Empty;
            string fix = finding.FixedVersions.Count == 0 ? "no fixed version known" : "fixed in " + string.Join(", ", finding.FixedVersions);

            text.Append('\n');
            text.Append($"  {severity,-9} {TerminalText.Safe(finding.Id, 60)}  {TerminalText.Safe(finding.Package.Id, 80)} {finding.Package.Version} ({direct}{projects}); {fix}\n");

            if (finding.Summary is not null)
            {
                text.Append($"            {TerminalText.Safe(finding.Summary, 140)}\n");
            }
        }

        text.Append("\nMatching is by package version only: reachability of the vulnerable code is not considered yet.\n");
        return text.ToString();
    }

    private static int SeverityRank(string? severity) => severity?.ToUpperInvariant() switch
    {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MODERATE" or "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    };
}
