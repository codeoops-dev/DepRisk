using System.Globalization;
using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Data.Reach;
using DepRisk.Data.Risk;

namespace DepRisk.Data;

/// <summary>The uncertainty model's request: parameters, number of scenarios, optional seed, and the statistic that orders the findings.</summary>
public sealed record RiskRequest(LoadedRiskParameters Parameters, int Samples, ulong? Seed, string RankBy);

public sealed record RankPipelineOptions(
    string ScanPath,
    string AdvisoriesPath,
    string? EpssPath,
    string? KevPath,
    Ecosystem? Ecosystem,
    bool Strict,
    ReachOptions? Reach,
    RiskRequest? Risk);

/// <summary>The ranking, with the full reachability outcome (paths included) when reachability was asked for.</summary>
public sealed record RankPipelineOutcome(RankingOutcome Ranking, ReachOutcome? Reach);

/// <summary>
/// The whole analysis behind <c>rank</c>, <c>ci</c>, <c>explain</c>, and <c>vex</c>: scan, match, optionally reachability, baseline
/// ranking, optionally the risk model. One implementation, so that every command talks about the same findings.
/// </summary>
public static class RankPipeline
{
    public static RankPipelineOutcome Run(
        RankPipelineOptions options,
        ToolInfo tool,
        IAnalyzerProcess analyzer,
        Func<string, string?> getEnvironmentVariable,
        string baseDirectory)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(tool);

        RankingOutcome outcome;
        ReachOutcome? reached = null;

        if (options.Reach is null)
        {
            outcome = RankingService.Rank(options.ScanPath, options.AdvisoriesPath, options.EpssPath, options.KevPath, tool, options.Strict, options.Ecosystem);
        }
        else
        {
            // Reachability is computed first (it matches the advisories itself); the ranking reuses those findings.
            reached = ReachService.Run(options.Reach, tool, analyzer, getEnvironmentVariable, baseDirectory);

            RankingOutcome ranked = RankingService.Rank(
                options.ScanPath, options.AdvisoriesPath, options.EpssPath, options.KevPath, tool, options.Strict, options.Ecosystem, reached.Findings);

            outcome = ranked with
            {
                Result = RankingService.WithReachability(ranked.Result, reached.Result),
                InputsDigest = Digest.Sha256Hex(ranked.InputsDigest + "\n" + reached.InputsDigest + "\n"),
            };
        }

        if (options.Risk is { } risk)
        {
            try
            {
                outcome = outcome with
                {
                    Result = RankingService.WithRiskModel(outcome.Result, risk.Parameters, risk.Samples, risk.Seed, risk.RankBy),
                    InputsDigest = Digest.Sha256Hex(
                        $"{outcome.InputsDigest}\nrisk:{risk.Parameters.ParametersDigest}|{risk.Samples}|{risk.Seed?.ToString(CultureInfo.InvariantCulture) ?? "default"}|{risk.RankBy}\n"),
                };
            }
            catch (ArgumentException ex)
            {
                // The model refuses too much work (findings x samples); that is an input problem.
                throw new InvalidInputException(ex.Message, ex);
            }
        }

        return new RankPipelineOutcome(outcome, reached);
    }
}
