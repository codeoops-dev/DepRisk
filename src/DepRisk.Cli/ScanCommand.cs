using System.Text;
using DepRisk.Audit;
using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Data;

namespace DepRisk.Cli;

/// <summary>
/// <c>deprisk scan [path] [--format table|json] [--out file]</c>:
/// reads the restored dependency graph (project.assets.json) of every project under <c>path</c>.
/// Static, offline, read-only (apart from the optional output file and, in an initialized project, the audit log).
/// </summary>
internal static class ScanCommand
{
    private static readonly string[] SupportedFormats = ["table", "json"];

    public static ExitCode Run(string[] args, TextWriter output, CliContext context)
    {
        string path = ".";
        string format = "table";
        string? outFile = null;
        bool pathSet = false;

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];

            if (arg is "--format" or "-f")
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
            else if (arg.StartsWith('-'))
            {
                throw new InvalidInputException($"unknown option '{arg}' for 'scan'.");
            }
            else if (!pathSet)
            {
                path = arg;
                pathSet = true;
            }
            else
            {
                throw new InvalidInputException("'scan' takes at most one path.");
            }
        }

        if (!SupportedFormats.Contains(format, StringComparer.Ordinal))
        {
            throw new InvalidInputException(
                $"format '{format}' is not supported for 'scan' (supported: {string.Join(", ", SupportedFormats)}).");
        }

        string scanPath = Path.GetFullPath(path, context.WorkingDirectory);
        ScanOutcome outcome = ScanService.ScanDetailed(scanPath, new ToolInfo(ProductInfo.CommandName, VersionInfo.Current));

        // The audited output is always the canonical JSON, so the digest does not depend on the chosen format.
        string json = ScanResultJson.Serialize(outcome.Result);
        string text = format == "json" ? json : RenderTable(outcome.Result);

        List<AuditChange> changes = [];

        if (outFile is not null)
        {
            string outPath = Path.GetFullPath(outFile, context.WorkingDirectory);
            bool existed = File.Exists(outPath);
            WriteFile(outPath, outFile, text);
            changes.Add(new AuditChange(outFile.Replace('\\', '/'), existed ? "existing file" : null, "written"));
        }

        AuditRecorder.RecordIfEnabled(
            context,
            new AuditDraft("scan", ArgRedactor.Redact(args), outcome.InputsDigest, Digest.Sha256Hex(json), changes));

        if (outFile is null)
        {
            output.Write(text);
        }
        else
        {
            output.Write($"Wrote {format} scan result to {outFile}\n");
        }

        return ExitCode.Success;
    }

    private static void WriteFile(string fullPath, string displayPath, string text)
    {
        try
        {
            File.WriteAllText(fullPath, text, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InvalidInputException($"cannot write '{displayPath}' ({ex.Message})", ex);
        }
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

    private static string RenderTable(ScanResult result)
    {
        StringBuilder text = new();
        text.Append($"deprisk scan: {result.Projects.Count} project(s), ecosystem {result.Ecosystem}\n");

        foreach (ProjectGraph project in result.Projects)
        {
            text.Append('\n');
            text.Append($"{project.Name}  ({project.AssetsFile})\n");

            foreach (TargetGraph target in project.Targets)
            {
                int direct = target.Packages.Count(p => p.IsDirect);
                int transitive = target.Packages.Count - direct;
                text.Append($"  {target.Name}: {target.Packages.Count} package(s) ({direct} direct, {transitive} transitive)\n");

                int idWidth = target.Packages.Count == 0 ? 0 : target.Packages.Max(p => p.Id.Length);
                int versionWidth = target.Packages.Count == 0 ? 0 : target.Packages.Max(p => p.Version.Length);

                foreach (ResolvedPackage package in target.Packages)
                {
                    string kind = package.IsDirect ? "direct" : "transitive";
                    text.Append($"    {package.Id.PadRight(idWidth)}  {package.Version.PadRight(versionWidth)}  {kind}\n");
                }
            }
        }

        return text.ToString();
    }
}
