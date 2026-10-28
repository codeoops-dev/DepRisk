namespace DepRisk.Cli.Tests;

internal static class TestContext
{
    public static readonly DateTimeOffset FixedTime = new(2026, 10, 27, 12, 0, 0, TimeSpan.Zero);

    /// <summary>A context that works in <paramref name="directory"/>, with a fixed clock and a fixed identity.</summary>
    public static CliContext For(string directory) => new(directory, () => FixedTime, "tester", "test-host");
}
