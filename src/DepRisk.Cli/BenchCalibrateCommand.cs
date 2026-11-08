using System.Globalization;
using System.Text;
using DepRisk.Audit;
using DepRisk.Core;
using DepRisk.Core.Bench;
using DepRisk.Core.Model;
using DepRisk.Data;
using DepRisk.Data.Bench;
using DepRisk.Data.Reach;
using DepRisk.Data.Risk;

namespace DepRisk.Cli;

/// <summary>
/// <c>deprisk bench calibrate --cases &lt;manifest.json&gt; --out &lt;risk-params.json&gt; [--risk-params file] [--prior uniform|current] [--min-count n]</c>:
/// fits the Reach factor on the development split and writes a complete parameters file (docs/benchmarks.md). It does not evaluate:
/// judge the result with <c>deprisk bench --split test --risk-params &lt;file&gt;</c>.
/// </summary>
internal static class BenchCalibrateCommand
{
    private const int DefaultTimeoutSeconds = 300;
    private const int MaxTimeoutSeconds = 3600;

    public static ExitCode Run(string[] args, TextWriter output, CliContext context)
    {
        string? cases = null;
        string? outFile = null;
        string? start = null;
        string priorText = "uniform";
        string minCountText = ReachCalibration.DefaultMinCount.ToString(CultureInfo.InvariantCulture);
        string? analyzer = null;
        string timeoutText = DefaultTimeoutSeconds.ToString(CultureInfo.InvariantCulture);
        bool strict = false;

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];

            if (ReachArgs.TryValue(args, ref i, arg, "--cases", "-c", out string? value))
            {
                cases = value;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--out", "-o", out value))
            {
                outFile = value;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--risk-params", null, out value))
            {
                start = value;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--prior", null, out value))
            {
                priorText = value!;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--min-count", null, out value))
            {
                minCountText = value!;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--analyzer", null, out value))
            {
                analyzer = value;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--timeout", null, out value))
            {
                timeoutText = value!;
            }
            else if (arg == "--strict")
            {
                strict = true;
            }
            else if (arg.StartsWith('-'))
            {
                throw new InvalidInputException($"unknown option '{TerminalText.Safe(arg, 40)}' for 'bench calibrate'.");
            }
            else
            {
                throw new InvalidInputException("'bench calibrate' takes no positional argument: pass the benchmark with --cases <manifest.json>.");
            }
        }

        if (cases is null)
        {
            throw new InvalidInputException("'bench calibrate' needs a benchmark manifest: deprisk bench calibrate --cases <manifest.json> --out <risk-params.json>.");
        }

        if (outFile is null)
        {
            throw new InvalidInputException("'bench calibrate' needs --out <risk-params.json>: the fitted parameters are written there.");
        }

        ReachPrior prior = priorText switch
        {
            "uniform" => ReachPrior.Uniform,
            "current" => ReachPrior.Current,
            _ => throw new InvalidInputException("--prior must be 'uniform' or 'current'."),
        };

        if (!int.TryParse(minCountText, NumberStyles.None, CultureInfo.InvariantCulture, out int minCount) || minCount < 1 || minCount > ReachCalibration.MaxMinCount)
        {
            throw new InvalidInputException($"--min-count must be a whole number from 1 to {ReachCalibration.MaxMinCount}.");
        }

        if (!int.TryParse(timeoutText, NumberStyles.None, CultureInfo.InvariantCulture, out int timeout) || timeout < 1 || timeout > MaxTimeoutSeconds)
        {
            throw new InvalidInputException($"--timeout must be a whole number of seconds from 1 to {MaxTimeoutSeconds}.");
        }

        LoadedRiskParameters startParameters = start is null
            ? RiskParametersLoader.Defaults()
            : RiskParametersLoader.Load(Path.GetFullPath(start, context.WorkingDirectory));

        LoadedBenchManifest manifest = BenchManifestLoader.Load(Path.GetFullPath(cases, context.WorkingDirectory));
        ToolInfo tool = new(ProductInfo.CommandName, VersionInfo.Current);

        BenchCalibrationOutcome outcome = BenchCalibrationService.Run(
            new BenchCalibrationOptions(
                manifest,
                startParameters,
                prior,
                minCount,
                strict,
                analyzer is null ? null : Path.GetFullPath(analyzer, context.WorkingDirectory),
                TimeSpan.FromSeconds(timeout),
                context.WorkingDirectory),
            tool,
            new AnalyzerProcess(),
            Environment.GetEnvironmentVariable);

        string json = RiskParametersWriter.Write(outcome.Parameters, outcome.Provenance);
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

        AuditRecorder.RecordIfEnabled(
            context,
            new AuditDraft(
                "bench-calibrate",
                ArgRedactor.Redact(args),
                outcome.InputsDigest,
                Digest.Sha256Hex(json),
                [new AuditChange(outFile.Replace('\\', '/'), existed ? "existing file" : null, "written")]));

        output.Write(Render(outcome, prior, minCount, outFile, cases));

        return ExitCode.Success;
    }

    private static string Render(BenchCalibrationOutcome r, ReachPrior prior, int minCount, string outFile, string cases)
    {
        StringBuilder text = new();

        text.Append($"deprisk bench calibrate: {TerminalText.Safe(r.Dataset.Name, 80)}, split {BenchCalibrationService.SplitUsed}: {r.Cases} case(s), {r.Observations} finding(s) with a reachability truth\n");
        text.Append($"Reach fitted per label as a Beta posterior; prior: {(prior == ReachPrior.Uniform ? "uniform Beta(1, 1)" : "the starting parameters")}; a label needs {minCount} or more findings with a known truth to be fitted\n");

        foreach (string warning in r.Warnings)
        {
            text.Append($"WARNING: {TerminalText.Safe(warning, 300)}\n");
        }

        text.Append($"\n  {"label",-20}{"n",6}{"reachable",11}{"observed",10}  {"before",-14}{"after",-14}\n");

        foreach (ReachLabelFit f in r.Fit.Labels)
        {
            string observed = f.ObservedRate is null ? "-" : f.ObservedRate.Value.ToString("0.000", CultureInfo.InvariantCulture);
            string after = f.Fitted ? Beta(f.After) : "kept";
            text.Append($"  {f.Label,-20}{f.Count,6}{f.TrulyReachable,11}{observed,10}  {Beta(f.Before),-14}{after,-14}\n");
        }

        text.Append($"\nWrote the parameters to {outFile} (all numbers, with a provenance note; Exploit and Impact are as they were).\n");
        text.Append($"Do not judge them on the data they were fitted on. Evaluate on the held-out split: deprisk bench --cases {cases} --split test --risk-params {outFile}\n");

        return text.ToString();
    }

    private static string Beta(DepRisk.Core.Risk.BetaParams b) =>
        $"({b.Alpha.ToString("0.##", CultureInfo.InvariantCulture)}, {b.Beta.ToString("0.##", CultureInfo.InvariantCulture)})";
}
