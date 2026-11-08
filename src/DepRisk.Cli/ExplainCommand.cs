using System.Text;
using DepRisk.Audit;
using DepRisk.Core;
using DepRisk.Core.Explain;
using DepRisk.Core.Model;
using DepRisk.Data;
using DepRisk.Data.Reach;

namespace DepRisk.Cli;

/// <summary>
/// <c>deprisk explain &lt;advisory-id&gt; [path] [--package id] (analysis options as for rank) [--format table|json] [--out file]</c>:
/// why a finding stands where it does: the evidence behind it, the reachability path, the risk distribution, and what would change
/// the picture. Offline; every sentence is built from the data by a fixed template.
/// </summary>
internal static class ExplainCommand
{
    private static readonly string[] SupportedFormats = ["table", "json"];

    public static ExitCode Run(string[] args, TextWriter output, CliContext context)
    {
        AnalysisArgs analysis = new();
        string? query = null;
        string path = ".";
        bool pathSet = false;
        string? package = null;
        string format = "table";
        string? outFile = null;

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];

            if (analysis.TryRead(args, ref i, arg, "explain"))
            {
                continue;
            }

            if (ReachArgs.TryValue(args, ref i, arg, "--package", "-p", out string? value))
            {
                package = value;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--format", "-f", out value))
            {
                format = value!;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--out", "-o", out value))
            {
                outFile = value;
            }
            else if (arg.StartsWith('-'))
            {
                throw new InvalidInputException($"unknown option '{arg}' for 'explain'.");
            }
            else if (query is null)
            {
                query = arg;
            }
            else if (!pathSet)
            {
                path = arg;
                pathSet = true;
            }
            else
            {
                throw new InvalidInputException("'explain' takes an advisory id and at most one path.");
            }
        }

        if (query is null)
        {
            throw new InvalidInputException("'explain' needs the advisory id (or an alias such as a CVE id): deprisk explain <id> [path] --advisories <...>");
        }

        if (!SupportedFormats.Contains(format, StringComparer.Ordinal))
        {
            throw new InvalidInputException($"format '{format}' is not supported for 'explain' (supported: {string.Join(", ", SupportedFormats)}).");
        }

        ToolInfo tool = new(ProductInfo.CommandName, VersionInfo.Current);
        RankPipelineOutcome pipeline = RankPipeline.Run(
            analysis.ToPipelineOptions("explain", Path.GetFullPath(path, context.WorkingDirectory), context),
            tool,
            new AnalyzerProcess(),
            Environment.GetEnvironmentVariable,
            AppContext.BaseDirectory);

        ExplainResult result = Explainer.Explain(pipeline.Ranking.Result, pipeline.Reach?.Result, tool, query, package);

        string json = ExplainResultJson.Serialize(result);
        string text = format == "json" ? json : RenderTable(result);

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
            new AuditDraft("explain", ArgRedactor.Redact(args), pipeline.Ranking.InputsDigest, Digest.Sha256Hex(json), changes));

        output.Write(outFile is null ? text : $"Wrote {format} explanation to {outFile} ({result.Findings.Count} finding(s))\n");
        return ExitCode.Success;
    }

    private static string RenderTable(ExplainResult result)
    {
        StringBuilder text = new();
        text.Append($"deprisk explain {TerminalText.Safe(result.Query, 80)}: {result.Findings.Count} finding(s), ecosystem {Ecosystem.FromId(result.Ecosystem).DisplayName}, method {result.Method}\n");

        foreach (ExplainFinding item in result.Findings)
        {
            RankedFinding f = item.Finding;
            string aliases = f.Aliases.Count == 0 ? string.Empty : $" (also {TerminalText.Safe(string.Join(", ", f.Aliases), 100)})";

            text.Append($"\n{TerminalText.Safe(f.Package.Id, 80)} {TerminalText.Safe(f.Package.Version, 40)}: {TerminalText.Safe(f.Id, 60)}{aliases}\n");

            if (f.Summary is not null)
            {
                text.Append($"  {TerminalText.Safe(f.Summary, 160)}\n");
            }

            Section(text, "where it stands", item.Position.Why);
            Section(text, "evidence", item.Evidence);
            Section(text, "what would change it", item.WhatWouldChange);
        }

        text.Append("\nEvery line is built from the data in the result (see --format json). Labels describe a conservative call graph, not exploitability.\n");
        return text.ToString();
    }

    private static void Section(StringBuilder text, string title, IReadOnlyList<string> lines)
    {
        text.Append($"  {title}:\n");

        foreach (string line in lines)
        {
            text.Append($"    - {TerminalText.Safe(line, 400)}\n");
        }
    }
}
