namespace DepRisk.Core.Model;

/// <summary>Who produced a result.</summary>
public sealed record ToolInfo(string Name, string Version);

/// <summary>A declared dependency of a package: the package id and the version range it asks for.</summary>
public sealed record DependencyRef(string Id, string Range);

/// <summary>
/// A package as resolved by the package manager for one target. <c>Requested</c> is the version constraint the project
/// itself asked for, as written in the assets or lock file (for example <c>&gt;= 1.2.0</c> for NuGet, <c>^4.17.0</c> for npm);
/// null for transitive packages. <c>Path</c> identifies the installed instance when the same package id can be installed
/// several times in one project (npm: the lock file key, for example <c>node_modules/a/node_modules/b</c>); null for NuGet,
/// where a project has one version of each package per target.
/// </summary>
public sealed record ResolvedPackage(
    string Id,
    string Version,
    bool IsDirect,
    IReadOnlyList<DependencyRef> Dependencies,
    string? Requested = null,
    string? Path = null);

/// <summary>The resolved package set for one target framework (or framework/runtime pair).</summary>
public sealed record TargetGraph(string Name, IReadOnlyList<ResolvedPackage> Packages);

/// <summary>
/// The dependency graph of one project. <c>AssetsFile</c> is the file the graph was read from (NuGet <c>project.assets.json</c>,
/// npm <c>package-lock.json</c>). <c>ProjectFile</c> is the project file (for example <c>src/App/App.csproj</c> or
/// <c>web/package.json</c>) relative to the scanned directory, with forward slashes, when it can be determined; null otherwise.
/// It lets tools such as code scanning attach results to a file that exists in the repository.
/// </summary>
public sealed record ProjectGraph(
    string Name,
    string AssetsFile,
    IReadOnlyList<TargetGraph> Targets,
    string? ProjectFile = null);

/// <summary>
/// Result of <c>deprisk scan</c>. This is a public contract: see schemas/scan-result.v1.schema.json.
/// It contains no timestamps or machine-specific paths so that the same input always gives the same output.
/// </summary>
public sealed record ScanResult(
    int SchemaVersion,
    ToolInfo Tool,
    string Ecosystem,
    IReadOnlyList<ProjectGraph> Projects)
{
    public const int CurrentSchemaVersion = 1;
}
