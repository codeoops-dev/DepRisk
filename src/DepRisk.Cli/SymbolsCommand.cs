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

    public static ExitCode Run(string[] args, TextWriter output, CliContext context)
    {
        if (args.Length == 0 || args[0] != "template")
        {
            throw new InvalidInputException(
                args.Length == 0
                    ? "'symbols' needs a subcommand. Available: template."
                    : $"unknown symbols subcommand '{SafeText.Clean(args[0], 40)}'. Available: template.");
        }

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

            if (ReachArgs.TryValue(args, ref i, arg, "--advisories", "-a", out string? value))
            {
                advisories = value;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--symbols", "-s", out value))
            {
                symbols = value;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--format", "-f", out value))
            {
                format = value!;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--out", "-o", out value))
            {
                outFile = value;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, EcosystemOption.Name, null, out value))
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
}
