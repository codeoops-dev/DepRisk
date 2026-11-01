using System.Text;
using DepRisk.Audit;
using DepRisk.Core;
using DepRisk.Core.Hypergraph;
using DepRisk.Core.Model;
using DepRisk.Data.Hypergraph;

namespace DepRisk.Cli;

/// <summary>
/// <c>deprisk graph [path] [--format table|json|dot] [--out file]</c>: the dependency hypergraph of the resolved graph,
/// with every requirement checked against the resolved versions (violated and undecided requirements are listed).
/// Static, offline, read-only (apart from the optional output file and, in an initialized project, the audit log).
/// </summary>
internal static class GraphCommand
{
    private static readonly string[] SupportedFormats = ["table", "json", "dot"];

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
                throw new InvalidInputException($"unknown option '{arg}' for 'graph'.");
            }
            else if (!pathSet)
            {
                path = arg;
                pathSet = true;
            }
            else
            {
                throw new InvalidInputException("'graph' takes at most one path.");
            }
        }

        if (!SupportedFormats.Contains(format, StringComparer.Ordinal))
        {
            throw new InvalidInputException(
                $"format '{format}' is not supported for 'graph' (supported: {string.Join(", ", SupportedFormats)}).");
        }

        HypergraphOutcome outcome = HypergraphService.Build(
            Path.GetFullPath(path, context.WorkingDirectory),
            new ToolInfo(ProductInfo.CommandName, VersionInfo.Current));

        string json = HypergraphResultJson.Serialize(outcome.Result);

        string text = format switch
        {
            "json" => json,
            "dot" => DotExporter.Export(outcome.Result),
            _ => RenderTable(outcome.Result),
        };

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
            new AuditDraft("graph", ArgRedactor.Redact(args), outcome.InputsDigest, Digest.Sha256Hex(json), changes));

        if (outFile is null)
        {
            output.Write(text);
        }
        else
        {
            output.Write($"Wrote {format} hypergraph to {outFile}\n");
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

    private static string RenderTable(HypergraphResult result)
    {
        StringBuilder text = new();
        text.Append($"deprisk graph: {result.Projects.Count} project(s), ecosystem {result.Ecosystem}\n");

        foreach (ProjectHypergraph project in result.Projects)
        {
            text.Append('\n');
            text.Append($"{TerminalText.Safe(project.Name, 80)}  ({TerminalText.Safe(project.ProjectFile ?? "project file unknown", 120)})\n");

            foreach (TargetHypergraph target in project.Targets)
            {
                HypergraphStats stats = target.Stats;
                text.Append(
                    $"  {TerminalText.Safe(target.Name, 60)}: {stats.Nodes} node(s) ({stats.DirectNodes} direct), "
                    + $"{stats.Hyperedges} hyperedge(s) (max arity {stats.MaxArity}), {stats.Requirements} requirement(s): "
                    + $"{stats.Violated} violated, {stats.Unresolved} undecided, {stats.SharedRequirements} shared\n");

                foreach (Hyperedge edge in target.Hyperedges)
                {
                    foreach (Requirement requirement in edge.Requires.Where(r => r.Satisfied == false).Take(20))
                    {
                        text.Append(
                            $"    VIOLATED  {TerminalText.Safe(edge.Owner, 100)} requires {TerminalText.Safe(requirement.Package, 80)} "
                            + $"{TerminalText.Safe(requirement.Range ?? "?", 60)} but the project resolved {TerminalText.Safe(requirement.Resolved ?? "?", 40)}\n");
                    }
                }

                foreach (Requirement requirement in target.Hyperedges.SelectMany(e => e.Requires.Where(r => r.Satisfied is null).Select(r => r)).Take(10))
                {
                    string reason = requirement.Resolved is null ? "not in the resolved graph" : "range not understood";
                    text.Append($"    undecided {TerminalText.Safe(requirement.Package, 80)} {TerminalText.Safe(requirement.Range ?? "?", 60)} ({reason})\n");
                }
            }
        }

        return text.ToString();
    }
}
