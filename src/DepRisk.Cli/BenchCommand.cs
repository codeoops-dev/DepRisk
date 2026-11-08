using System.Globalization;
using System.Text;
using DepRisk.Audit;
using DepRisk.Core;
using DepRisk.Core.Bench;
using DepRisk.Core.Model;
using DepRisk.Core.Risk;
using DepRisk.Data;
using DepRisk.Data.Bench;
using DepRisk.Data.Reach;
using DepRisk.Data.Risk;

namespace DepRisk.Cli;

/// <summary>
/// <c>deprisk bench --cases &lt;manifest.json&gt; [--split dev|test|all] [model and bootstrap options] [--format table|json] [--out file]</c>:
/// runs the analysis on a labeled benchmark and compares the baselines with the risk model (docs/benchmarks.md). Offline.
/// A benchmark is evidence only when its dataset is; a synthetic one says so in every output.
/// </summary>
internal static class BenchCommand
{
    private const int DefaultSamples = 5000;
    private const int DefaultBootstrap = 1000;
    private const int DefaultTimeoutSeconds = 300;
    private const int MaxTimeoutSeconds = 3600;
    private static readonly string[] SupportedFormats = ["table", "json"];

    public static ExitCode Run(string[] args, TextWriter output, CliContext context)
    {
        if (args.Length > 0 && args[0] == "calibrate")
        {
            return BenchCalibrateCommand.Run(args[1..], output, context);
        }

        string? cases = null;
        string split = "dev";
        string samplesText = DefaultSamples.ToString(CultureInfo.InvariantCulture);
        string? seedText = null;
        string rankByText = "mean";
        string? riskParams = null;
        string bootstrapText = DefaultBootstrap.ToString(CultureInfo.InvariantCulture);
        string? analyzer = null;
        string timeoutText = DefaultTimeoutSeconds.ToString(CultureInfo.InvariantCulture);
        bool strict = false;
        string format = "table";
        string? outFile = null;

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];

            if (ReachArgs.TryValue(args, ref i, arg, "--cases", "-c", out string? value))
            {
                cases = value;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--split", null, out value))
            {
                split = value!;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--samples", null, out value))
            {
                samplesText = value!;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--seed", null, out value))
            {
                seedText = value;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--rank-by", null, out value))
            {
                rankByText = value!;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--risk-params", null, out value))
            {
                riskParams = value;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--bootstrap", null, out value))
            {
                bootstrapText = value!;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--analyzer", null, out value))
            {
                analyzer = value;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--timeout", null, out value))
            {
                timeoutText = value!;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--format", "-f", out value))
            {
                format = value!;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--out", "-o", out value))
            {
                outFile = value;
            }
            else if (arg == "--strict")
            {
                strict = true;
            }
            else if (arg.StartsWith('-'))
            {
                throw new InvalidInputException($"unknown option '{TerminalText.Safe(arg, 40)}' for 'bench'.");
            }
            else
            {
                throw new InvalidInputException("'bench' takes no positional argument: pass the benchmark with --cases <manifest.json>.");
            }
        }

        if (cases is null)
        {
            throw new InvalidInputException("'bench' needs a benchmark manifest: deprisk bench --cases <manifest.json> (docs/benchmarks.md).");
        }

        if (!SupportedFormats.Contains(format, StringComparer.Ordinal))
        {
            throw new InvalidInputException($"format '{TerminalText.Safe(format, 20)}' is not supported for 'bench' (supported: {string.Join(", ", SupportedFormats)}).");
        }

        if (!BenchService.Splits.Contains(split, StringComparer.Ordinal))
        {
            throw new InvalidInputException($"--split must be one of: {string.Join(", ", BenchService.Splits)}.");
        }

        if (!int.TryParse(samplesText, NumberStyles.None, CultureInfo.InvariantCulture, out int samples) || samples < RiskModel.MinSamples || samples > RiskModel.MaxSamples)
        {
            throw new InvalidInputException($"--samples must be a whole number from {RiskModel.MinSamples} to {RiskModel.MaxSamples}.");
        }

        ulong? seed = null;

        if (seedText is not null)
        {
            seed = ulong.TryParse(seedText, NumberStyles.None, CultureInfo.InvariantCulture, out ulong parsed)
                ? parsed
                : throw new InvalidInputException("--seed must be a whole number from 0 to 18446744073709551615.");
        }

        string rankBy = RiskRanker.NormalizeStatistic(rankByText)
            ?? throw new InvalidInputException($"--rank-by must be one of: {string.Join(", ", RiskRanker.Statistics)} (cvar is accepted for cvar95).");

        if (!int.TryParse(bootstrapText, NumberStyles.None, CultureInfo.InvariantCulture, out int bootstrap) || bootstrap > Bootstrap.MaxIterations)
        {
            throw new InvalidInputException($"--bootstrap must be a whole number from 0 (off) to {Bootstrap.MaxIterations}.");
        }

        if (!int.TryParse(timeoutText, NumberStyles.None, CultureInfo.InvariantCulture, out int timeout) || timeout < 1 || timeout > MaxTimeoutSeconds)
        {
            throw new InvalidInputException($"--timeout must be a whole number of seconds from 1 to {MaxTimeoutSeconds}.");
        }

        LoadedRiskParameters parameters = riskParams is null
            ? RiskParametersLoader.Defaults()
            : RiskParametersLoader.Load(Path.GetFullPath(riskParams, context.WorkingDirectory));

        LoadedBenchManifest manifest = BenchManifestLoader.Load(Path.GetFullPath(cases, context.WorkingDirectory));
        ToolInfo tool = new(ProductInfo.CommandName, VersionInfo.Current);

        BenchOutcome outcome = BenchService.Run(
            new BenchOptions(
                manifest,
                split,
                new RiskRequest(parameters, samples, seed, rankBy),
                strict,
                bootstrap,
                analyzer is null ? null : Path.GetFullPath(analyzer, context.WorkingDirectory),
                TimeSpan.FromSeconds(timeout),
                context.WorkingDirectory),
            tool,
            new AnalyzerProcess(),
            Environment.GetEnvironmentVariable);

        string json = BenchResultJson.Serialize(outcome.Result);
        string text = format == "json" ? json : RenderTable(outcome.Result);

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
            new AuditDraft("bench", ArgRedactor.Redact(args), outcome.InputsDigest, Digest.Sha256Hex(json), changes));

        output.Write(outFile is null
            ? text
            : $"Wrote {format} benchmark result to {outFile} ({outcome.Result.Counts.Labeled} labeled finding(s) in {outcome.Result.Counts.Cases} case(s))\n");

        return ExitCode.Success;
    }

    private static string RenderTable(BenchResult r)
    {
        StringBuilder text = new();
        BenchCounts c = r.Counts;

        text.Append($"deprisk bench: {TerminalText.Safe(r.Dataset.Name, 80)}, split {r.Split}: {c.Cases} case(s), {c.Labeled} labeled finding(s), {c.Exploited} exploited\n");
        text.Append($"signals as of {r.Dataset.SignalsAsOf}; outcomes observed {r.Dataset.OutcomeFrom} to {r.Dataset.OutcomeTo}; dataset {r.Dataset.Digest[..12]}\n");
        text.Append($"risk model: {r.Model.Samples} samples, seed {r.Model.Seed} ({r.Model.SeedSource}), ordered by {r.Model.RankBy}, parameters: {r.Model.Calibration}\n");

        foreach (string warning in r.Warnings)
        {
            text.Append($"WARNING: {TerminalText.Safe(warning, 300)}\n");
        }

        text.Append("\nOrdering quality (macro average over cases with an exploited finding; higher AP is better, lower alert fraction is better):\n");
        text.Append($"  {"method",-22}{"AP",8}  {"95% CI",-17}{"alerts to full recall",-23}{"recall@1",9}{"@3",7}{"@5",7}{"@10",7}  suppressed  missed\n");

        foreach (BenchMethodResult m in r.Methods)
        {
            string alerts = m.AlertFractionToFullRecall is null
                ? "-"
                : $"{Num(m.AlertFractionToFullRecall)} ({m.CasesFullRecall}/{m.CasesWithPositives})";

            text.Append($"  {m.Id,-22}{Num(m.AveragePrecision),8}  {Ci(m.AveragePrecisionCi),-17}{alerts,-23}");

            foreach (AtK k in m.AtK)
            {
                text.Append(Num(k.Recall).PadLeft(k.K == 1 ? 9 : 7));
            }

            text.Append($"  {m.Suppressed,10}  {m.ExploitedMissed,6}\n");
        }

        if (r.Bootstrap.NotComputedReason is { } reason)
        {
            text.Append($"  (no intervals: {reason})\n");
        }
        else
        {
            text.Append($"  (intervals: {r.Bootstrap.Iterations} case-level bootstrap resamples, seed {r.Bootstrap.Seed}; 'alerts to full recall' counts only cases where all exploited findings are presented, shown as n/N)\n");
        }

        text.Append("\nPaired differences, risk model minus the other method (same resampled cases):\n");

        foreach (BenchDifference d in r.Differences)
        {
            text.Append($"  {d.Metric,-27} vs {d.Versus,-22}{Num(d.Difference),8}  {Ci(d.Ci)}\n");
        }

        if (r.Reach is { } reach)
        {
            text.Append($"\nReachability against ground truth ({reach.Evaluated} finding(s)); coverage {Num(reach.Coverage)}:\n");
            text.Append($"  {"label",-20}{"truly reachable",16}{"not reachable",15}\n");

            foreach (ReachConfusionRow row in reach.Rows)
            {
                text.Append($"  {row.Label,-20}{row.TruthReachable,16}{row.TruthNotReachable,15}\n");
            }

            text.Append($"  unsound 'unreachable' calls: {reach.UnsoundUnreachable} of {reach.UnreachableTotal}\n");
            text.Append($"  strict (reachable only): precision {Num(reach.Strict.Precision)}, recall {Num(reach.Strict.Recall)}; lenient (with possibly-reachable): precision {Num(reach.Lenient.Precision)}, recall {Num(reach.Lenient.Recall)}\n");
        }
        else
        {
            text.Append("\nReachability against ground truth: no finding was both analyzed and labeled with a reachability truth.\n");
        }

        text.Append("\nCalibration (Brier and log loss: lower is better; ECE: gap between predicted and observed, lower is better):\n");

        foreach (CalibrationReport cal in r.Calibration)
        {
            CalibrationSummary s = cal.Summary;
            text.Append($"  {cal.Quantity,-14} n={s.Count,-5} base rate {Num(s.BaseRate)}  Brier {Num(s.Brier)}  log loss {Num(s.LogLoss)}  ECE {Num(s.Ece)}\n");
        }

        text.Append("\nObserved reachable rate against the model's Reach factor, by label:\n");

        foreach (ReachLabelCalibration row in r.ReachByLabel.Where(row => row.Count > 0))
        {
            text.Append($"  {row.Label,-20} n={row.Count,-5} observed {Num(row.ObservedReachableRate)}  predicted {Num(row.MeanPredictedReach)}\n");
        }

        text.Append("\nNot evaluated yet:\n");

        foreach (NotEvaluated item in r.NotEvaluated)
        {
            text.Append($"  {item.Metric}: {item.Reason}\n");
        }

        return text.ToString();
    }

    private static string Num(double? value) => value is null ? "-" : value.Value.ToString("0.000", CultureInfo.InvariantCulture);

    private static string Ci(Interval? interval) =>
        interval is null ? string.Empty : $"[{interval.Low.ToString("0.000", CultureInfo.InvariantCulture)}, {interval.High.ToString("0.000", CultureInfo.InvariantCulture)}]";
}
