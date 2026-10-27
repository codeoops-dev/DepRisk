using System.Text;
using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Data;

namespace DepRisk.Cli;

/// <summary>
/// <c>deprisk scan [path] [--format table|json] [--out file]</c>:
/// reads the restored dependency graph (project.assets.json) of every project under <c>path</c>.
/// Static, offline, read-only (apart from the optional output file).
/// </summary>
internal static class ScanCommand
{
    private static readonly string[] SupportedFormats = ["table", "json"];

    public static ExitCode Run(string[] args, TextWriter output)
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

        ScanResult result = ScanService.Scan(path, new ToolInfo(ProductInfo.CommandName, VersionInfo.Current));
        string text = format == "json" ? ScanResultJson.Serialize(result) : RenderTable(result);

        if (outFile is null)
        {
            output.Write(text);
            return ExitCode.Success;
        }

        try
        {
            File.WriteAllText(outFile, text, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InvalidInputException($"cannot write '{outFile}' ({ex.Message})", ex);
        }

        output.Write($"Wrote {format} scan result to {outFile}\n");
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
