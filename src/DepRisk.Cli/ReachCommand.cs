using System.Text;
using DepRisk.Audit;
using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Core.Reach;
using DepRisk.Data;
using DepRisk.Data.Reach;

namespace DepRisk.Cli;

/// <summary>
/// <c>deprisk reach [path] --advisories &lt;...&gt; --symbols &lt;file|dir&gt; [--source dir] [--entrypoints auto|public-api|none]
/// [--entrypoint Ns.Type.Method]... [--analyzer file] [--timeout seconds] [--ecosystem ...] [--format table|json] [--out file] [--strict]</c>:
/// for every advisory that applies, says whether the vulnerable code can be reached from the application (ADR 0012, ADR 0013).
/// Offline. The labels describe a conservative call graph, not exploitability.
/// </summary>
internal static class ReachCommand
{
    private static readonly string[] SupportedFormats = ["table", "json"];
    private static readonly string[] EntrypointModes = ["auto", "public-api", "none"];
    private const int DefaultTimeoutSeconds = 300;
    private const int MaxTimeoutSeconds = 3600;

    public static ExitCode Run(string[] args, TextWriter output, CliContext context)
    {
        string path = ".";
        string? advisories = null;
        string? symbols = null;
        string? source = null;
        string? analyzer = null;
        string mode = "auto";
        List<string> explicitEntrypoints = [];
        int timeoutSeconds = DefaultTimeoutSeconds;
        string format = "table";
        Ecosystem? ecosystem = null;
        string? outFile = null;
        bool strict = false;
        bool pathSet = false;

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];

            if (TryValue(args, ref i, arg, "--advisories", "-a", out string? value))
            {
                advisories = value;
            }
            else if (TryValue(args, ref i, arg, "--symbols", "-s", out value))
            {
                symbols = value;
            }
            else if (TryValue(args, ref i, arg, "--source", null, out value))
            {
                source = value;
            }
            else if (TryValue(args, ref i, arg, "--analyzer", null, out value))
            {
                analyzer = value;
            }
            else if (TryValue(args, ref i, arg, "--entrypoints", null, out value))
            {
                mode = value!;
            }
            else if (TryValue(args, ref i, arg, "--entrypoint", null, out value))
            {
                explicitEntrypoints.Add(value!);
            }
            else if (TryValue(args, ref i, arg, "--timeout", null, out value))
            {
                if (!int.TryParse(value, out timeoutSeconds) || timeoutSeconds < 1 || timeoutSeconds > MaxTimeoutSeconds)
                {
                    throw new InvalidInputException($"--timeout must be a whole number of seconds from 1 to {MaxTimeoutSeconds}.");
                }
            }
            else if (TryValue(args, ref i, arg, "--format", "-f", out value))
            {
                format = value!;
            }
            else if (TryValue(args, ref i, arg, "--out", "-o", out value))
            {
                outFile = value;
            }
            else if (TryValue(args, ref i, arg, EcosystemOption.Name, null, out value))
            {
                ecosystem = EcosystemOption.Parse(value!, "reach");
            }
            else if (arg == "--strict")
            {
                strict = true;
            }
            else if (arg.StartsWith('-'))
            {
                throw new InvalidInputException($"unknown option '{arg}' for 'reach'.");
            }
            else if (!pathSet)
            {
                path = arg;
                pathSet = true;
            }
            else
            {
                throw new InvalidInputException("'reach' takes at most one path.");
            }
        }

        if (!SupportedFormats.Contains(format, StringComparer.Ordinal))
        {
            throw new InvalidInputException($"format '{format}' is not supported for 'reach' (supported: {string.Join(", ", SupportedFormats)}).");
        }

        if (!EntrypointModes.Contains(mode, StringComparer.Ordinal))
        {
            throw new InvalidInputException($"--entrypoints must be one of: {string.Join(", ", EntrypointModes)}.");
        }

        foreach (string name in explicitEntrypoints)
        {
            if (!SymbolSyntax.IsValid(name) || name.EndsWith(".#ctor", StringComparison.Ordinal))
            {
                throw new InvalidInputException($"--entrypoint '{SafeText.Clean(name, 80)}' is not a method name (Namespace.Type.Method, or Namespace.Type.* for every member).");
            }
        }

        if (advisories is null)
        {
            throw new InvalidInputException(
                "'reach' needs advisory data: pass --advisories <directory | .zip | .json> (OSV format), as for 'match'.");
        }

        if (symbols is null)
        {
            throw new InvalidInputException(
                "'reach' needs symbol maps: pass --symbols <file | directory> (docs/symbol-maps.md). OSV has no symbol data for NuGet, "
                + "so the symbols through which a flaw is reached must come from a symbol map.");
        }

        ReachOptions options = new(
            Path.GetFullPath(path, context.WorkingDirectory),
            Path.GetFullPath(advisories, context.WorkingDirectory),
            Path.GetFullPath(symbols, context.WorkingDirectory),
            source,
            ecosystem,
            strict,
            mode,
            explicitEntrypoints,
            analyzer,
            TimeSpan.FromSeconds(timeoutSeconds),
            context.WorkingDirectory);

        ReachOutcome outcome = ReachService.Run(
            options,
            new ToolInfo(ProductInfo.CommandName, VersionInfo.Current),
            new AnalyzerProcess(),
            Environment.GetEnvironmentVariable,
            AppContext.BaseDirectory);

        string json = ReachabilityResultJson.Serialize(outcome.Result);
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
            new AuditDraft("reach", ArgRedactor.Redact(args), outcome.InputsDigest, Digest.Sha256Hex(json), changes));

        if (outFile is null)
        {
            output.Write(text);
        }
        else
        {
            ReachSummary s = outcome.Result.Summary;
            output.Write($"Wrote {format} reachability to {outFile} ({s.Reachable} reachable, {s.PossiblyReachable} possibly reachable, {s.Unreachable} unreachable, {s.Unknown} unknown)\n");
        }

        return ExitCode.Success;
    }

    private static bool TryValue(string[] args, ref int index, string arg, string longName, string? shortName, out string? value)
    {
        value = null;

        if (arg == longName || (shortName is not null && arg == shortName))
        {
            if (index + 1 >= args.Length)
            {
                throw new InvalidInputException($"option '{arg}' needs a value.");
            }

            index++;
            value = args[index];
            return true;
        }

        if (arg.StartsWith(longName + "=", StringComparison.Ordinal))
        {
            value = arg[(longName.Length + 1)..];
            return true;
        }

        return false;
    }

    private static string Describe(string reason) => reason switch
    {
        ReachLabels.StaticPath => "a call path exists",
        ReachLabels.DynamicPath => "a path exists only through dynamic edges (dispatch, reflection by name, calls on values of unknown type)",
        ReachLabels.NoPath => "no path from any entrypoint",
        ReachLabels.NoSymbols => "no symbol list for this advisory (add one with --symbols)",
        ReachLabels.NoEntrypoints => "no entrypoint found (for a library use --entrypoints public-api; or name one with --entrypoint)",
        ReachLabels.SymbolListIncomplete => "no path found, but the symbol list is not declared complete",
        ReachLabels.IncompleteAnalysis => "some source could not be read completely",
        ReachLabels.UnresolvedReflection => "reflection with a target that cannot be read is reachable",
        ReachLabels.UnresolvedReceiver => "a call on a value of unknown type could reach it",
        ReachLabels.TransitivePackage => "transitive dependency: its own code is not analyzed, so absence of a path proves nothing",
        ReachLabels.NoAnalyzerForEcosystem => "there is no reachability analyzer for this ecosystem yet",
        _ => TerminalText.Safe(reason, 60),
    };

    private static string RenderTable(ReachOutcome outcome)
    {
        ReachabilityResult result = outcome.Result;
        StringBuilder text = new();

        text.Append($"deprisk reach: {result.Findings.Count} finding(s), ecosystem {Ecosystem.FromId(result.Ecosystem).DisplayName}\n");
        text.Append($"advisories: {TerminalText.Safe(result.Advisories.Source, 80)}  {result.Advisories.Count} advisories, sha256 {result.Advisories.Digest[..12]}\n");
        text.Append($"symbol maps: {TerminalText.Safe(result.SymbolMaps.Source, 80)}  {result.SymbolMaps.Entries} entr{(result.SymbolMaps.Entries == 1 ? "y" : "ies")}, sha256 {result.SymbolMaps.Digest[..12]}\n");

        if (result.Analyzer is not null && result.Source is not null)
        {
            text.Append($"analyzer: {TerminalText.Safe(result.Analyzer.Name, 40)} {TerminalText.Safe(result.Analyzer.Version, 40)}, sha256 {result.Analyzer.Sha256[..12]}\n");
            text.Append($"source: {result.Source.Files} file(s) analyzed ({result.Source.FilesWithErrors} with unreadable syntax, {result.Source.FilesSkipped} skipped), {result.Source.Entrypoints} entrypoint(s), sha256 {result.Source.SourceDigest[..12]}\n");
        }
        else
        {
            text.Append("analyzer: not run\n");
        }

        ReachSummary s = result.Summary;
        text.Append($"summary: {s.Reachable} reachable, {s.PossiblyReachable} possibly reachable, {s.Unknown} unknown, {s.Unreachable} unreachable\n");

        foreach (string diagnostic in result.Diagnostics.Take(5))
        {
            text.Append($"note: {TerminalText.Safe(diagnostic, 200)}\n");
        }

        foreach (ReachFinding item in result.Findings)
        {
            Finding finding = item.Finding;
            ReachVerdict verdict = item.Reachability;
            string direct = finding.Locations.Any(l => l.IsDirect) ? "direct" : "transitive";

            text.Append('\n');
            text.Append($"  {verdict.Label,-18} {TerminalText.Safe(finding.Id, 60)}  {TerminalText.Safe(finding.Package.Id, 80)} {TerminalText.Safe(finding.Package.Version, 40)} ({direct})\n");
            text.Append($"  {string.Empty,-18} {Describe(verdict.Reason)}\n");

            if (verdict.Symbol is not null)
            {
                text.Append($"  {string.Empty,-18} via {TerminalText.Safe(verdict.Symbol, 120)}\n");
            }

            if (verdict.Path.Count > 0)
            {
                text.Append($"  {string.Empty,-18} {RenderPath(verdict.Path)}\n");
            }

            if (verdict.SymbolSources.Count > 0)
            {
                text.Append($"  {string.Empty,-18} symbols from: {TerminalText.Safe(string.Join("; ", verdict.SymbolSources), 160)}\n");
            }
        }

        text.Append("\nLabels describe a conservative call graph built from source, not exploitability. 'unreachable' is only said when nothing could hide a path and the symbol list is declared complete (docs/adr/0012-reachability-analyzer.md).\n");
        return text.ToString();
    }

    private static string RenderPath(IReadOnlyList<ReachPathEdge> path)
    {
        List<string> names = path.Select(e => TerminalText.Safe(e.From, 80)).ToList();
        names.Add(TerminalText.Safe(path[^1].To, 80));

        if (names.Count > 7)
        {
            names = [.. names.Take(3), "...", .. names.TakeLast(3)];
        }

        ReachPathEdge last = path[^1];
        string where = last.File is null ? string.Empty : $"  ({TerminalText.Safe(last.File, 80)}{(last.Line is null ? string.Empty : ":" + last.Line)})";
        string dynamic = path.Any(e => e.Kind == "dynamic") ? "  [uses dynamic edges]" : string.Empty;

        return string.Join(" -> ", names) + where + dynamic;
    }
}
