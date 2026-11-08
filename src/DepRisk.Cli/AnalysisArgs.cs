using DepRisk.Core;
using DepRisk.Core.Risk;
using DepRisk.Data;
using DepRisk.Data.Risk;

namespace DepRisk.Cli;

/// <summary>
/// The options that describe an analysis (what <c>rank</c> computes), for the commands that explain or export it:
/// <c>--advisories</c>, <c>--epss</c>, <c>--kev</c>, <c>--ecosystem</c>, <c>--strict</c>, the reachability options, and the risk model options.
/// </summary>
internal sealed class AnalysisArgs
{
    private string? _advisories;
    private string? _epss;
    private string? _kev;
    private Ecosystem? _ecosystem;
    private string _model = "baseline";
    private string _samples = "5000";
    private string? _seed;
    private string _rankBy = "mean";
    private string? _riskParams;
    private bool _riskOptionGiven;

    public ReachArgs Reach { get; } = new();

    public bool Strict { get; private set; }

    public bool TryRead(string[] args, ref int index, string arg, string commandName)
    {
        if (Reach.TryRead(args, ref index, arg))
        {
            return true;
        }

        if (ReachArgs.TryValue(args, ref index, arg, "--advisories", "-a", out string? value))
        {
            _advisories = value;
        }
        else if (ReachArgs.TryValue(args, ref index, arg, "--epss", null, out value))
        {
            _epss = value;
        }
        else if (ReachArgs.TryValue(args, ref index, arg, "--kev", null, out value))
        {
            _kev = value;
        }
        else if (ReachArgs.TryValue(args, ref index, arg, EcosystemOption.Name, null, out value))
        {
            _ecosystem = EcosystemOption.Parse(value!, commandName);
        }
        else if (ReachArgs.TryValue(args, ref index, arg, "--model", null, out value))
        {
            _model = value!;
        }
        else if (ReachArgs.TryValue(args, ref index, arg, "--samples", null, out value))
        {
            _samples = value!;
            _riskOptionGiven = true;
        }
        else if (ReachArgs.TryValue(args, ref index, arg, "--seed", null, out value))
        {
            _seed = value;
            _riskOptionGiven = true;
        }
        else if (ReachArgs.TryValue(args, ref index, arg, "--rank-by", null, out value))
        {
            _rankBy = value!;
            _riskOptionGiven = true;
        }
        else if (ReachArgs.TryValue(args, ref index, arg, "--risk-params", null, out value))
        {
            _riskParams = value;
            _riskOptionGiven = true;
        }
        else if (arg == "--strict")
        {
            Strict = true;
        }
        else
        {
            return false;
        }

        return true;
    }

    public RankPipelineOptions ToPipelineOptions(string commandName, string scanPath, CliContext context)
    {
        if (_advisories is null)
        {
            throw new InvalidInputException($"'{commandName}' needs advisory data: pass --advisories <directory | .zip | .json> (OSV format), as for 'match'.");
        }

        Reach.Validate(commandName, symbolsRequired: false);

        if (_model is not ("baseline" or "risk"))
        {
            throw new InvalidInputException($"--model must be 'baseline' (the reference ordering) or 'risk' (the uncertainty model), not '{TerminalText.Safe(_model, 40)}'.");
        }

        if (_model == "baseline" && _riskOptionGiven)
        {
            throw new InvalidInputException($"'{commandName}': --samples, --seed, --rank-by, and --risk-params only apply with --model risk.");
        }

        RiskRequest? risk = null;

        if (_model == "risk")
        {
            if (!int.TryParse(_samples, out int samples) || samples < RiskModel.MinSamples || samples > RiskModel.MaxSamples)
            {
                throw new InvalidInputException($"--samples must be a whole number from {RiskModel.MinSamples} to {RiskModel.MaxSamples}.");
            }

            ulong? seed = null;

            if (_seed is not null)
            {
                seed = ulong.TryParse(_seed, out ulong parsed) ? parsed : throw new InvalidInputException("--seed must be a whole number from 0 to 18446744073709551615.");
            }

            string rankBy = RiskRanker.NormalizeStatistic(_rankBy)
                ?? throw new InvalidInputException($"--rank-by must be one of: {string.Join(", ", RiskRanker.Statistics)} (cvar is accepted for cvar95).");

            LoadedRiskParameters parameters = _riskParams is null
                ? RiskParametersLoader.Defaults()
                : RiskParametersLoader.Load(Path.GetFullPath(_riskParams, context.WorkingDirectory));

            risk = new RiskRequest(parameters, samples, seed, rankBy);
        }

        string advisories = Path.GetFullPath(_advisories, context.WorkingDirectory);

        return new RankPipelineOptions(
            scanPath,
            advisories,
            _epss is null ? null : Path.GetFullPath(_epss, context.WorkingDirectory),
            _kev is null ? null : Path.GetFullPath(_kev, context.WorkingDirectory),
            _ecosystem,
            Strict,
            Reach.Symbols is null ? null : Reach.ToOptions(scanPath, advisories, _ecosystem, Strict, context),
            risk);
    }
}
