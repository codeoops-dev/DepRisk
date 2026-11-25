namespace DepRisk.Cli;

/// <summary>
/// Everything a command may need to know about the process it runs in. Passing it explicitly keeps commands
/// testable (fixed clock, isolated working directory) and keeps global state out of the audit log code.
/// </summary>
internal sealed record CliContext(
    string WorkingDirectory,
    Func<DateTimeOffset> Clock,
    string Actor,
    string Host,
    Func<string, string?>? EnvironmentReader = null)
{
    public static CliContext Default() =>
        new(Environment.CurrentDirectory, () => DateTimeOffset.UtcNow, Environment.UserName, Environment.MachineName);

    /// <summary>
    /// An environment variable, as the commands see it. The variables that name a signing key and its passphrase are read through
    /// here, so a test can give them without touching the environment of the process.
    /// </summary>
    public string? GetEnvironmentVariable(string name) =>
        EnvironmentReader is null ? Environment.GetEnvironmentVariable(name) : EnvironmentReader(name);
}
