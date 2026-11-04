namespace DepRisk.Data.Tests;

/// <summary>Real package-lock.json files written by npm (tests/fixtures/npm), embedded in this test assembly.</summary>
internal static class NpmFixtures
{
    /// <summary>A web project: scoped package, an alias install, an optional dependency, and one package installed twice (ms 2.0.0 and 2.1.3).</summary>
    public const string Simple = "simple.package-lock.json";

    /// <summary>A workspace root with two members: links, first-party entries, and copies nested inside a member.</summary>
    public const string Workspaces = "workspaces.package-lock.json";

    public static string Read(string name) => ReadResource("npm/" + name);

    /// <summary>A file of tests/fixtures/reach (the reachability fixtures), for example "osv/DEPRISK-EXAMPLE-0001.json".</summary>
    public static string ReadReach(string name) => ReadResource("reach/" + name.Replace('/', Path.DirectorySeparatorChar));

    private static string ReadResource(string logicalName)
    {
        using Stream stream = typeof(NpmFixtures).Assembly.GetManifestResourceStream(logicalName)
            ?? throw new InvalidOperationException($"fixture '{logicalName}' is not embedded.");
        using StreamReader reader = new(stream);
        return reader.ReadToEnd();
    }
}
