using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Core.Reach;

namespace DepRisk.Data.Reach;

public sealed record SymbolCheckOptions(string ScanPath, string AdvisoriesPath, string SymbolsPath, Ecosystem? Ecosystem, bool Strict);

public sealed record SymbolCheckOutcome(
    string Ecosystem,
    string Language,
    AdvisorySourceInfo Advisories,
    SymbolMapInfo SymbolMaps,
    SymbolCheckResult Result,
    string InputsDigest);

/// <summary><c>deprisk symbols check</c> (ADR 0025): scans and matches the project as <c>reach</c> does, loads the maps, and checks that they still fit.</summary>
public static class SymbolCheckService
{
    public static SymbolCheckOutcome Run(SymbolCheckOptions options, ToolInfo tool)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(tool);

        FindingsOutcome matched = FindingsService.Match(options.ScanPath, options.AdvisoriesPath, tool, options.Strict, options.Ecosystem);
        FindingsResult findings = matched.Result;

        string language = ReachService.LanguageOf(findings.Ecosystem)
            ?? throw new InvalidInputException($"there is no analyzer for the ecosystem '{SafeText.Clean(findings.Ecosystem, 40)}', so there are no symbol maps for it.");

        LoadedSymbolMaps maps = SymbolMapLoader.Load(options.SymbolsPath);
        SymbolCheckResult result = SymbolCheck.Evaluate(findings.Findings, maps.Map, language);
        string inputs = Digest.Sha256Hex($"findings:{matched.InputsDigest}\nsymbols:{maps.Info.Digest}\n");

        return new SymbolCheckOutcome(findings.Ecosystem, language, findings.Advisories, maps.Info, result, inputs);
    }
}
