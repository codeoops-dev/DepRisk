namespace DepRisk.Cli.Tests;

internal static class TestContext
{
    public static readonly DateTimeOffset FixedTime = new(2026, 10, 27, 12, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// A context that works in <paramref name="directory"/>, with a fixed clock and a fixed identity. The variables that name a signing
    /// key and its passphrase are not taken from the process, so a developer's own settings cannot change a test.
    /// </summary>
    public static CliContext For(string directory) => For(directory, new Dictionary<string, string>());

    /// <summary>The same, with these environment variables (and none of the process's DEPRISK_KEY_ variables).</summary>
    public static CliContext For(string directory, IReadOnlyDictionary<string, string> environment) =>
        new(
            directory,
            () => FixedTime,
            "tester",
            "test-host",
            name => environment.TryGetValue(name, out string? value)
                ? value
                : name.StartsWith("DEPRISK_KEY_", StringComparison.Ordinal) ? null : Environment.GetEnvironmentVariable(name));
}
