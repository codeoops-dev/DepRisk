using DepRisk.Core;

namespace DepRisk.Data.Reach;

/// <summary>
/// Finds the reachability analyzer executable. The order is: the <c>--analyzer</c> option, the <c>DEPRISK_REACH</c> environment
/// variable, the directory of the CLI. The <c>PATH</c> is deliberately not searched: a program that parses untrusted source
/// code and is started by a security tool must be one the user named or installed with the tool, not whatever is first on PATH.
/// </summary>
public static class AnalyzerLocator
{
    public const string EnvironmentVariable = "DEPRISK_REACH";

    public static string ExecutableName => OperatingSystem.IsWindows() ? "deprisk-reach.exe" : "deprisk-reach";

    /// <returns>The full path, or null if there is none. Throws if an explicit choice does not exist.</returns>
    public static string? Find(string? explicitPath, string workingDirectory, Func<string, string?> getEnvironmentVariable, string baseDirectory)
    {
        ArgumentNullException.ThrowIfNull(getEnvironmentVariable);

        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            return RequireFile(Path.GetFullPath(explicitPath, workingDirectory), "--analyzer");
        }

        string? fromEnvironment = getEnvironmentVariable(EnvironmentVariable);

        if (!string.IsNullOrWhiteSpace(fromEnvironment))
        {
            return RequireFile(Path.GetFullPath(fromEnvironment, workingDirectory), EnvironmentVariable);
        }

        string sibling = Path.Combine(baseDirectory, ExecutableName);

        return File.Exists(sibling) ? sibling : null;
    }

    private static string RequireFile(string path, string source)
    {
        if (!File.Exists(path))
        {
            throw new InvalidInputException($"the analyzer given by {source} does not exist: {SafeText.Clean(path, 200)}");
        }

        return path;
    }

    public static string NotFoundMessage() =>
        "reachability analysis needs the analyzer (" + ExecutableName + "). Build it with 'cargo build --release --locked' in analyzers/reach "
        + $"and pass --analyzer <path>, set {EnvironmentVariable}, or put it next to the deprisk executable. "
        + "(deprisk does not search PATH for it.) See docs/adr/0013-reach-command.md.";
}
