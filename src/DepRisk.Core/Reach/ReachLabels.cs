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

    /// <summary>The reason in words, for people (the machine-readable reason stays in the result).</summary>
    public static string Describe(string reason) => reason switch
    {
        StaticPath => "a call path exists",
        DynamicPath => "a path exists only through dynamic edges (dispatch, reflection by name, calls on values of unknown type)",
        NoPath => "no path from any entrypoint",
        NoSymbols => "no symbol list for this advisory (add one with --symbols)",
        NoEntrypoints => "no entrypoint found (for a library use --entrypoints public-api; or name one with --entrypoint)",
        SymbolListIncomplete => "no path found, but the symbol list is not declared complete",
        IncompleteAnalysis => "some source could not be read completely",
        UnresolvedReflection => "reflection with a target that cannot be read is reachable",
        UnresolvedReceiver => "a call on a value of unknown type could reach it",
        TransitivePackage => "transitive dependency: its own code is not analyzed, so absence of a path proves nothing",
        NoAnalyzerForEcosystem => "there is no reachability analyzer for this ecosystem yet",
        _ => "unrecognized reason",
    };

    /// <summary>Most urgent first: what a person should look at first.</summary>
    public static int Priority(string label) => label switch
    {
        Reachable => 0,
        PossiblyReachable => 1,
        Unknown => 2,
        _ => 3,
    };
}
