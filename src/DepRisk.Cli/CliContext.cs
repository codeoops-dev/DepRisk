namespace DepRisk.Cli;

/// <summary>
/// Everything a command may need to know about the process it runs in. Passing it explicitly keeps commands
/// testable (fixed clock, isolated working directory) and keeps global state out of the audit log code.
/// </summary>
internal sealed record CliContext(string WorkingDirectory, Func<DateTimeOffset> Clock, string Actor, string Host)
{
    public static CliContext Default() =>
        new(Environment.CurrentDirectory, () => DateTimeOffset.UtcNow, Environment.UserName, Environment.MachineName);
}
