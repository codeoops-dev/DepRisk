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
    private readonly RiskOptionArgs _risk = new(5000);

    public ReachArgs Reach { get; } = new();

    public bool Strict { get; private set; }

    public bool TryRead(string[] args, ref int index, string arg, string commandName)
    {
        if (Reach.TryRead(args, ref index, arg))
        {
            return true;
        }

        if (_risk.TryRead(args, ref index, arg))
        {
            return true;
        }

        if (OptionValue.TryValue(args, ref index, arg, "--advisories", "-a", out string? value))
        {
            _advisories = value;
        }
        else if (OptionValue.TryValue(args, ref index, arg, "--epss", null, out value))
        {
            _epss = value;
        }
        else if (OptionValue.TryValue(args, ref index, arg, "--kev", null, out value))
        {
            _kev = value;
        }
        else if (OptionValue.TryValue(args, ref index, arg, EcosystemOption.Name, null, out value))
        {
            _ecosystem = EcosystemOption.Parse(value!, commandName);
        }
        else if (OptionValue.TryValue(args, ref index, arg, "--model", null, out value))
        {
            _model = value!;
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

    /// <summary>Checks that <c>--advisories</c> was given. A command that wants its own wording for the error passes it as <paramref name="message"/>.</summary>
    public void RequireAdvisories(string commandName, string? message = null)
    {
        if (_advisories is null)
        {
            throw new InvalidInputException(message ?? $"'{commandName}' needs advisory data: pass --advisories <directory | .zip | .json> (OSV format), as for 'match'.");
        }
    }

    public RankPipelineOptions ToPipelineOptions(string commandName, string scanPath, CliContext context)
    {
        RequireAdvisories(commandName);
        string advisoriesOption = _advisories!;

        Reach.Validate(commandName, symbolsRequired: false);

        if (_model is not ("baseline" or "risk"))
        {
            throw new InvalidInputException($"--model must be 'baseline' (the reference ordering) or 'risk' (the uncertainty model), not '{TerminalText.Safe(_model, 40)}'.");
        }

        if (_model == "baseline" && _risk.AnyGiven)
        {
            throw new InvalidInputException($"'{commandName}': --samples, --seed, --rank-by, and --risk-params only apply with --model risk.");
        }

        RiskRequest? risk = null;

        if (_model == "risk")
        {
            _risk.Validate();
            risk = _risk.Build(context);
        }

        string advisories = Path.GetFullPath(advisoriesOption, context.WorkingDirectory);

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
