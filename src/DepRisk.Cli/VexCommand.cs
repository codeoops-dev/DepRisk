using System.Globalization;
using System.Text;
using DepRisk.Audit;
using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Data;
using DepRisk.Data.OpenVex;
using DepRisk.Data.Reach;

namespace DepRisk.Cli;

/// <summary>
/// <c>deprisk vex [path] --product &lt;purl|iri&gt; --author &lt;text&gt; [--role text] [--timestamp rfc3339] (analysis options) [--out file]</c>:
/// an OpenVEX 0.2.0 document with one statement per finding. <c>not_affected</c> only for findings proven unreachable under the
/// strict conditions (ADR 0016); <c>affected</c> with an action for reachable ones; everything else <c>under_investigation</c>.
/// </summary>
internal static class VexCommand
{
    public static ExitCode Run(string[] args, TextWriter output, CliContext context)
    {
        AnalysisArgs analysis = new();
        string path = ".";
        bool pathSet = false;
        string? product = null;
        string? author = null;
        string? role = null;
        string? timestampText = null;
        string? outFile = null;

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];

            if (analysis.TryRead(args, ref i, arg, "vex"))
            {
                continue;
            }

            if (ReachArgs.TryValue(args, ref i, arg, "--product", null, out string? value))
            {
                product = value;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--author", null, out value))
            {
                author = value;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--role", null, out value))
            {
                role = value;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--timestamp", null, out value))
            {
                timestampText = value;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--out", "-o", out value))
            {
                outFile = value;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--format", "-f", out value))
            {
                if (value != "json")
                {
                    throw new InvalidInputException("'vex' writes OpenVEX, which is JSON: --format json is the only format.");
                }
            }
            else if (arg.StartsWith('-'))
            {
                throw new InvalidInputException($"unknown option '{arg}' for 'vex'.");
            }
            else if (!pathSet)
            {
                path = arg;
                pathSet = true;
            }
            else
            {
                throw new InvalidInputException("'vex' takes at most one path.");
            }
        }

        string productValue = Required(product, "--product", "the product the statements are about, as a Package URL or an IRI (for example pkg:nuget/MyApp@1.0.0)", 500);
        string authorValue = Required(author, "--author", "who makes these statements (a person, a team, or an organization)", 200);

        if (role is not null && (role.Length > 200 || role.Any(char.IsControl)))
        {
            throw new InvalidInputException("--role is too long or contains control characters.");
        }

        DateTimeOffset timestamp;

        if (timestampText is null)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            timestamp = new DateTimeOffset(now.Year, now.Month, now.Day, now.Hour, now.Minute, now.Second, TimeSpan.Zero);
        }
        else if (!DateTimeOffset.TryParse(timestampText, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out timestamp))
        {
            throw new InvalidInputException("--timestamp must be an RFC 3339 date and time, for example 2026-11-05T12:00:00Z.");
        }

        ToolInfo tool = new(ProductInfo.CommandName, VersionInfo.Current);
        RankPipelineOutcome pipeline = RankPipeline.Run(
            analysis.ToPipelineOptions("vex", Path.GetFullPath(path, context.WorkingDirectory), context),
            tool,
            new AnalyzerProcess(),
            Environment.GetEnvironmentVariable,
            AppContext.BaseDirectory);

        string json = OpenVexWriter.Serialize(
            pipeline.Ranking.Result,
            pipeline.Reach?.Result,
            new OpenVexOptions(productValue, authorValue, role, timestamp, $"{tool.Name} {tool.Version}"));

        List<AuditChange> changes = [];

        if (outFile is not null)
        {
            string outPath = Path.GetFullPath(outFile, context.WorkingDirectory);
            bool existed = File.Exists(outPath);

            try
            {
                File.WriteAllText(outPath, json, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new InvalidInputException($"cannot write '{outFile}' ({ex.Message})", ex);
            }

            changes.Add(new AuditChange(outFile.Replace('\\', '/'), existed ? "existing file" : null, "written"));
        }

        AuditRecorder.RecordIfEnabled(
            context,
            new AuditDraft("vex", ArgRedactor.Redact(args), pipeline.Ranking.InputsDigest, Digest.Sha256Hex(json), changes));

        if (outFile is null)
        {
            output.Write(json);
        }
        else
        {
            output.Write($"Wrote OpenVEX to {outFile} ({pipeline.Ranking.Result.Findings.Count} statement(s))\n");
        }

        return ExitCode.Success;
    }

    private static string Required(string? value, string option, string meaning, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidInputException($"'vex' needs {option}: {meaning}.");
        }

        if (value.Length > maxLength || value.Any(char.IsControl))
        {
            throw new InvalidInputException($"{option} is too long or contains control characters.");
        }

        return value;
    }
}
