namespace DepRisk.Core.Reach;

/// <summary>The labels and reasons of a reachability verdict (ADR 0012, ADR 0013).</summary>
public static class ReachLabels
{
    public const string Reachable = "reachable";
    public const string PossiblyReachable = "possibly-reachable";
    public const string Unreachable = "unreachable";
    public const string Unknown = "unknown";

    public static readonly IReadOnlyList<string> AllLabels = [Reachable, PossiblyReachable, Unreachable, Unknown];

    // Reasons the analyzer gives.
    public const string StaticPath = "static-path";
    public const string DynamicPath = "dynamic-path";
    public const string NoPath = "no-path";
    public const string NoSymbols = "no-symbols";
    public const string NoEntrypoints = "no-entrypoints";
    public const string SymbolListIncomplete = "symbol-list-incomplete";
    public const string IncompleteAnalysis = "incomplete-analysis";
    public const string UnresolvedReflection = "unresolved-reflection";
    public const string UnresolvedReceiver = "unresolved-receiver";

    // Reasons the CLI adds.
    public const string TransitivePackage = "transitive-package-code-not-analyzed";
    public const string NoAnalyzerForEcosystem = "no-analyzer-for-ecosystem";

    public static readonly IReadOnlyList<string> AnalyzerReasons =
    [
        StaticPath, DynamicPath, NoPath, NoSymbols, NoEntrypoints, SymbolListIncomplete, IncompleteAnalysis, UnresolvedReflection, UnresolvedReceiver,
    ];

    /// <summary>Most urgent first: what a person should look at first.</summary>
    public static int Priority(string label) => label switch
    {
        Reachable => 0,
        PossiblyReachable => 1,
        Unknown => 2,
        _ => 3,
    };
}
