using System.Text;
using DepRisk.Audit;
using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Core.Reach;
using DepRisk.Data;
using DepRisk.Data.Reach;

namespace DepRisk.Cli;

/// <summary>
/// <c>deprisk symbols template [path] --advisories &lt;...&gt; [--symbols &lt;file|dir&gt;] [--ecosystem ...] [--format table|json] [--out file] [--force] [--strict]</c>:
/// lists the advisory and package pairs of a project that have no symbol map entry and drafts an entry for each (ADR 0024). Offline;
/// it never guesses symbols. The draft is refused by every command that reads symbol maps until it is filled in.
/// </summary>
internal static class SymbolsCommand
{
    private static readonly string[] SupportedFormats = ["table", "json"];

    public static ExitCode Run(string[] args, TextWriter output, TextWriter error, CliContext context)
    {
        if (args.Length == 0 || args[0] is not ("template" or "check"))
        {
            throw new InvalidInputException(
                args.Length == 0
                    ? "'symbols' needs a subcommand. Available: template, check."
                    : $"unknown symbols subcommand '{SafeText.Clean(args[0], 40)}'. Available: template, check.");
        }

        return args[0] == "check" ? RunCheck(args, output, error, context) : RunTemplate(args, output, context);
    }

    private static ExitCode RunTemplate(string[] args, TextWriter output, CliContext context)
    {
        string path = ".";
        string? advisories = null;
        string? symbols = null;
        string format = "table";
        Ecosystem? ecosystem = null;
        string? outFile = null;
        bool strict = false;
        bool force = false;
        bool pathSet = false;

        for (int i = 1; i < args.Length; i++)
        {
            string arg = args[i];

            if (OptionValue.TryValue(args, ref i, arg, "--advisories", "-a", out string? value))
            {
                advisories = value;
            }
            else if (OptionValue.TryValue(args, ref i, arg, "--symbols", "-s", out value))
            {
                symbols = value;
            }
            else if (OptionValue.TryValue(args, ref i, arg, "--format", "-f", out value))
            {
                format = value!;
            }
            else if (OptionValue.TryValue(args, ref i, arg, "--out", "-o", out value))
            {
                outFile = value;
            }
            else if (OptionValue.TryValue(args, ref i, arg, EcosystemOption.Name, null, out value))
            {
                ecosystem = EcosystemOption.Parse(value!, "symbols template");
            }
            else if (arg == "--strict")
            {
                strict = true;
            }
            else if (arg == "--force")
            {
                force = true;
            }
            else if (arg.StartsWith('-'))
            {
                throw new InvalidInputException($"unknown option '{SafeText.Clean(arg, 60)}' for 'symbols template'.");
            }
            else if (!pathSet)
            {
                path = arg;
                pathSet = true;
            }
            else
            {
                throw new InvalidInputException("'symbols template' takes at most one path.");
            }
        }

        if (!SupportedFormats.Contains(format, StringComparer.Ordinal))
        {
            throw new InvalidInputException($"format '{SafeText.Clean(format, 40)}' is not supported for 'symbols template' (supported: {string.Join(", ", SupportedFormats)}).");
        }

        if (advisories is null)
        {
            throw new InvalidInputException("'symbols template' needs advisory data: pass --advisories <directory | .zip | .json> (OSV format), as for 'match'.");
        }

        if (force && outFile is null)
        {
            throw new InvalidInputException("--force only applies together with --out.");
        }

        SymbolTemplateOutcome outcome = SymbolTemplateService.Run(
            new SymbolTemplateOptions(
                Path.GetFullPath(path, context.WorkingDirectory),
                Path.GetFullPath(advisories, context.WorkingDirectory),
                symbols is null ? null : Path.GetFullPath(symbols, context.WorkingDirectory),
                ecosystem,
                strict),
            new ToolInfo(ProductInfo.CommandName, VersionInfo.Current));

        int missing = outcome.Items.Count(i => i.Status == SymbolWorkStatus.Missing);
        List<AuditChange> changes = [];
        string? writeNote = null;

        if (outFile is not null)
        {
            string outPath = Path.GetFullPath(outFile, context.WorkingDirectory);

            if (missing == 0)
            {
                writeNote = $"Nothing to write: no advisory and package pair is missing a symbol map entry, so {SafeText.Clean(outFile, 120)} was not created.";
            }
            else
            {
                // A draft that someone has filled in is hand-written work: it is never replaced without --force (other commands overwrite their output).
                if (File.Exists(outPath) && !force)
                {
                    throw new InvalidInputException($"'{SafeText.Clean(outFile, 120)}' already exists and may hold a filled-in symbol map; nothing was written. Choose another name, or pass --force to replace it.");
                }

                bool existed = File.Exists(outPath);

                try
                {
                    File.WriteAllText(outPath, outcome.DraftJson, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    throw new InvalidInputException($"cannot write '{SafeText.Clean(outFile, 120)}' ({ex.Message})", ex);
                }

                changes.Add(new AuditChange(outFile.Replace('\\', '/'), existed ? "existing file" : null, "written"));
                writeNote = $"Wrote a draft with {missing} entr{(missing == 1 ? "y" : "ies")} to {SafeText.Clean(outFile, 120)}.";
            }
        }

        AuditRecorder.RecordIfEnabled(
            context,
            new AuditDraft("symbols-template", ArgRedactor.Redact(args), outcome.InputsDigest, Digest.Sha256Hex(outcome.DraftJson), changes));

        if (format == "json")
        {
            output.Write(outFile is null ? outcome.DraftJson : writeNote + "\n");
        }
        else
        {
            output.Write(RenderTable(outcome, writeNote));
        }

        return ExitCode.Success;
    }

    private static string RenderTable(SymbolTemplateOutcome outcome, string? writeNote)
    {
        StringBuilder text = new();
        int missing = outcome.Items.Count(i => i.Status == SymbolWorkStatus.Missing);
        int covered = outcome.Items.Count(i => i.Status == SymbolWorkStatus.Covered);
        int unwritable = outcome.Items.Count(i => i.Status == SymbolWorkStatus.Unwritable);

        text.Append($"deprisk symbols template: {missing} to write, {covered} covered, {unwritable} not writable; ecosystem {Ecosystem.FromId(outcome.Ecosystem).DisplayName}, language {outcome.Language}\n");
        text.Append($"advisories: {TerminalText.Safe(outcome.Advisories.Source, 80)}  {outcome.Advisories.Count} advisories, sha256 {outcome.Advisories.Digest[..12]}\n");

        text.Append(outcome.SymbolMaps is { } maps
            ? $"symbol maps: {TerminalText.Safe(maps.Source, 80)}  {maps.Entries} entr{(maps.Entries == 1 ? "y" : "ies")}, sha256 {maps.Digest[..12]}\n"
            : "symbol maps: none given (every pair counts as missing; pass --symbols to leave out what is already written)\n");

        foreach (SymbolWorkItem item in outcome.Items)
        {
            string aliases = item.Aliases.Count == 0 ? string.Empty : $" ({TerminalText.Safe(string.Join(", ", item.Aliases.Take(4)), 80)}{(item.Aliases.Count > 4 ? ", ..." : string.Empty)})";
            string versions = TerminalText.Safe(string.Join(", ", item.InstalledVersions.Take(3)), 60) + (item.InstalledVersions.Count > 3 ? ", ..." : string.Empty);
            string where = item.Direct ? "direct" : "transitive";
            string label = item.Status switch
            {
                SymbolWorkStatus.Missing => "TODO",
                SymbolWorkStatus.Covered => item.ExistingComplete ? "covered" : "covered (incomplete)",
                _ => "NOT WRITABLE",
            };

            if (item.Status != SymbolWorkStatus.Covered)
            {
                text.Append('\n');
            }

            text.Append($"  {label,-20} {TerminalText.Safe(item.Advisory, 60)}{aliases}  {TerminalText.Safe(item.Package, 80)} {versions} ({where})\n");

            if (item.Status == SymbolWorkStatus.Covered)
            {
                continue;
            }

            if (item.Status == SymbolWorkStatus.Unwritable)
            {
                text.Append($"  {string.Empty,-20} {TerminalText.Safe(item.Problem, 120)}; no entry can be drafted for it\n");
                continue;
            }

            if (!string.IsNullOrWhiteSpace(item.Summary))
            {
                text.Append($"  {string.Empty,-20} {TerminalText.Safe(item.Summary, 160)}\n");
            }

            if (item.FixedVersions.Count > 0)
            {
                text.Append($"  {string.Empty,-20} fixed in: {TerminalText.Safe(string.Join(", ", item.FixedVersions.Take(5)), 80)}\n");
            }

            if (!item.Direct)
            {
                text.Append($"  {string.Empty,-20} transitive only: even a complete list cannot make this unreachable (its own code is not analyzed)\n");
            }
        }

        if (writeNote is not null)
        {
            text.Append('\n').Append(writeNote).Append('\n');
        }

        if (missing > 0)
        {
            text.Append("\nEach drafted entry has symbols [], complete null and source \"\" on purpose: commands that read symbol maps refuse the file until you have filled in all three.\n");
            text.Append("OSV carries no symbols for NuGet or npm, so none are proposed. See docs/symbol-maps.md for how to write them.\n");
        }

        return text.ToString();
    }

    private static ExitCode RunCheck(string[] args, TextWriter output, TextWriter error, CliContext context)
    {
        string path = ".";
        string? advisories = null;
        string? symbols = null;
        string? failOn = null;
        Ecosystem? ecosystem = null;
        bool strict = false;
        bool pathSet = false;

        for (int i = 1; i < args.Length; i++)
        {
            string arg = args[i];

            if (OptionValue.TryValue(args, ref i, arg, "--advisories", "-a", out string? value))
            {
                advisories = value;
            }
            else if (OptionValue.TryValue(args, ref i, arg, "--symbols", "-s", out value))
            {
                symbols = value;
            }
            else if (OptionValue.TryValue(args, ref i, arg, "--fail-on", null, out value))
            {
                failOn = value;
            }
            else if (OptionValue.TryValue(args, ref i, arg, EcosystemOption.Name, null, out value))
            {
                ecosystem = EcosystemOption.Parse(value!, "symbols check");
            }
            else if (arg == "--strict")
            {
                strict = true;
            }
            else if (arg.StartsWith('-'))
            {
                throw new InvalidInputException($"unknown option '{SafeText.Clean(arg, 60)}' for 'symbols check'.");
            }
            else if (!pathSet)
            {
                path = arg;
                pathSet = true;
            }
            else
            {
                throw new InvalidInputException("'symbols check' takes at most one path.");
            }
        }

        if (advisories is null)
        {
            throw new InvalidInputException("'symbols check' needs advisory data: pass --advisories <directory | .zip | .json> (OSV format), as for 'match'.");
        }

        if (symbols is null)
        {
            throw new InvalidInputException("'symbols check' needs the symbol maps to check: pass --symbols <file | directory> (docs/symbol-maps.md).");
        }

        IReadOnlySet<string>? gate = failOn is null ? null : SymbolCheck.ParseGate(failOn);

        SymbolCheckOutcome outcome = SymbolCheckService.Run(
            new SymbolCheckOptions(
                Path.GetFullPath(path, context.WorkingDirectory),
                Path.GetFullPath(advisories, context.WorkingDirectory),
                Path.GetFullPath(symbols, context.WorkingDirectory),
                ecosystem,
                strict),
            new ToolInfo(ProductInfo.CommandName, VersionInfo.Current));

        string text = RenderCheck(outcome);

        AuditRecorder.RecordIfEnabled(
            context,
            new AuditDraft("symbols-check", ArgRedactor.Redact(args), outcome.InputsDigest, Digest.Sha256Hex(text), []));

        output.Write(text);

        if (gate is null)
        {
            return ExitCode.Success;
        }

        IReadOnlyList<string> tripped = SymbolCheck.Tripped(outcome.Result, gate);

        if (tripped.Count == 0)
        {
            return ExitCode.Success;
        }

        error.WriteLine($"{ProductInfo.CommandName}: symbols check gate failed ({string.Join(", ", tripped)}).");
        return ExitCode.PolicyGateFailed;
    }

    private static string RenderCheck(SymbolCheckOutcome outcome)
    {
        SymbolCheckResult r = outcome.Result;
        StringBuilder text = new();

        text.Append($"deprisk symbols check: {r.Entries.Count} entr{(r.Entries.Count == 1 ? "y" : "ies")} for {outcome.Language}, {r.Pairs.Count} advisory/package pair(s) in the project; ecosystem {Ecosystem.FromId(outcome.Ecosystem).DisplayName}\n");
        text.Append($"advisories: {TerminalText.Safe(outcome.Advisories.Source, 80)}  {outcome.Advisories.Count} advisories, sha256 {outcome.Advisories.Digest[..12]}\n");
        text.Append($"symbol maps: {TerminalText.Safe(outcome.SymbolMaps.Source, 80)}  {outcome.SymbolMaps.Entries} entr{(outcome.SymbolMaps.Entries == 1 ? "y" : "ies")}, sha256 {outcome.SymbolMaps.Digest[..12]}\n");

        if (r.IgnoredOtherLanguage > 0)
        {
            text.Append($"ignored: {r.IgnoredOtherLanguage} entr{(r.IgnoredOtherLanguage == 1 ? "y" : "ies")} for the other language\n");
        }

        text.Append($"summary: {r.Applies} apply ({r.Applies - r.Incomplete} complete, {r.Incomplete} incomplete), {r.Unused} unused, {r.Missing} missing, {r.Unwritable} not writable\n");

        foreach (SymbolEntryCheck entry in r.Entries.Where(e => e.Status == SymbolEntryStatus.Unused))
        {
            text.Append($"\n  {"unused",-14} {TerminalText.Safe(entry.Advisory, 60)}  {TerminalText.Safe(entry.Package, 80)}\n");
            text.Append($"  {string.Empty,-14} no finding of this project matches it (the package is not installed at an affected version, or the advisory is not in the data given)\n");
        }

        foreach (SymbolEntryCheck entry in r.Entries.Where(e => e.Status == SymbolEntryStatus.Applies && !e.Complete))
        {
            text.Append($"\n  {"incomplete",-14} {TerminalText.Safe(entry.Advisory, 60)}  {TerminalText.Safe(entry.Package, 80)}\n");
            text.Append($"  {string.Empty,-14} complete: false, so the verdict is never 'unreachable' (source: {TerminalText.Safe(string.Join("; ", entry.Sources), 100)})\n");
        }

        foreach (SymbolEntryCheck entry in r.Entries.Where(e => e.Status == SymbolEntryStatus.Applies && e.Complete && !e.Direct))
        {
            text.Append($"\n  {"transitive",-14} {TerminalText.Safe(entry.Advisory, 60)}  {TerminalText.Safe(entry.Package, 80)}\n");
            text.Append($"  {string.Empty,-14} complete: true has no effect: the package is only a transitive dependency, so its own code is not analyzed\n");
        }

        foreach (SymbolWorkItem pair in r.Pairs.Where(p => p.Status != SymbolWorkStatus.Covered))
        {
            string label = pair.Status == SymbolWorkStatus.Missing ? "missing" : "not writable";
            text.Append($"\n  {label,-14} {TerminalText.Safe(pair.Advisory, 60)}  {TerminalText.Safe(pair.Package, 80)} {TerminalText.Safe(string.Join(", ", pair.InstalledVersions.Take(3)), 60)} ({(pair.Direct ? "direct" : "transitive")})\n");
            text.Append($"  {string.Empty,-14} {(pair.Status == SymbolWorkStatus.Missing ? "no entry yet; 'deprisk symbols template' drafts one" : TerminalText.Safe(pair.Problem, 120))}\n");
        }

        text.Append("\nThis checks that the maps still fit the project, not that the symbols are right or the lists really complete (ADR 0025).\n");
        return text.ToString();
    }
}
