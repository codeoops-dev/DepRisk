using System.Globalization;
using DepRisk.Core;
using DepRisk.Core.Risk;
using DepRisk.Data;
using DepRisk.Data.Risk;

namespace DepRisk.Cli;

/// <summary>
/// The risk model options <c>--samples</c>, <c>--seed</c>, <c>--rank-by</c> and <c>--risk-params</c>, with one set of rules and messages for
/// <c>rank</c>, <c>ci</c>, <c>explain</c>, <c>vex</c> (with <c>--model risk</c>) and <c>bench</c>. <see cref="Validate"/> checks the values
/// (samples, seed, statistic, in that order); <see cref="Build"/> loads the parameter file. They are two steps because a command may
/// validate other options in between.
/// </summary>
internal sealed class RiskOptionArgs(int defaultSamples)
{
    private string _samples = defaultSamples.ToString(CultureInfo.InvariantCulture);
    private string? _seed;
    private string _rankBy = "mean";
    private string? _riskParams;
    private int _samplesValue;
    private ulong? _seedValue;
    private string _rankByValue = "mean";

    /// <summary>True if any of the four options was given (with <c>--model baseline</c> they have nothing to act on).</summary>
    public bool AnyGiven { get; private set; }

    public bool TryRead(string[] args, ref int index, string arg)
    {
        if (OptionValue.TryValue(args, ref index, arg, "--samples", null, out string? value))
        {
            _samples = value!;
        }
        else if (OptionValue.TryValue(args, ref index, arg, "--seed", null, out value))
        {
            _seed = value;
        }
        else if (OptionValue.TryValue(args, ref index, arg, "--rank-by", null, out value))
        {
            _rankBy = value!;
        }
        else if (OptionValue.TryValue(args, ref index, arg, "--risk-params", null, out value))
        {
            _riskParams = value;
        }
        else
        {
            return false;
        }

        AnyGiven = true;
        return true;
    }

    public void Validate()
    {
        if (!OptionNumber.TryInt(_samples, out int samples) || samples < RiskModel.MinSamples || samples > RiskModel.MaxSamples)
        {
            throw new InvalidInputException($"--samples must be a whole number from {RiskModel.MinSamples} to {RiskModel.MaxSamples}.");
        }

        _samplesValue = samples;
        _seedValue = null;

        if (_seed is not null)
        {
            _seedValue = OptionNumber.TryULong(_seed, out ulong parsed) ? parsed : throw new InvalidInputException("--seed must be a whole number from 0 to 18446744073709551615.");
        }

        _rankByValue = RiskRanker.NormalizeStatistic(_rankBy)
            ?? throw new InvalidInputException($"--rank-by must be one of: {string.Join(", ", RiskRanker.Statistics)} (cvar is accepted for cvar95).");
    }

    /// <summary>Loads the parameter file (or the defaults) and returns the request. Call <see cref="Validate"/> first.</summary>
    public RiskRequest Build(CliContext context)
    {
        LoadedRiskParameters parameters = _riskParams is null
            ? RiskParametersLoader.Defaults()
            : RiskParametersLoader.Load(Path.GetFullPath(_riskParams, context.WorkingDirectory));

        return new RiskRequest(parameters, _samplesValue, _seedValue, _rankByValue);
    }
}
