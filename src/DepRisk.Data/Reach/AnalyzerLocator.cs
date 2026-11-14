using System.Runtime.InteropServices;
using DepRisk.Core;

namespace DepRisk.Data.Reach;

/// <summary>
/// Finds the reachability analyzer executable. The order is: the <c>--analyzer</c> option, the <c>DEPRISK_REACH</c> environment
/// variable, the directory of the CLI, and the analyzer that the NuGet package bundles for this platform
/// (<c>analyzers/&lt;rid&gt;/</c> next to the CLI, ADR 0022). The <c>PATH</c> is deliberately not searched: a program that parses
/// untrusted source code and is started by a security tool must be one the user named or installed with the tool, not whatever is
/// first on PATH.
/// </summary>
public static class AnalyzerLocator
{
    public const string EnvironmentVariable = "DEPRISK_REACH";

    public static string ExecutableName => OperatingSystem.IsWindows() ? "deprisk-reach.exe" : "deprisk-reach";

    /// <summary>The platforms the NuGet package bundles an analyzer for.</summary>
    public static readonly IReadOnlyList<string> BundledPlatforms = ["linux-x64", "linux-arm64", "osx-x64", "osx-arm64", "win-x64"];

    /// <summary>
    /// The runtime identifier of this machine (<c>linux-x64</c>, <c>osx-arm64</c>, <c>win-x64</c>, ...), built from the operating system and
    /// the process architecture rather than from the runtime's own identifier, which can carry a distribution name. Null for a platform
    /// this tool does not know.
    /// </summary>
    public static string? CurrentPlatform() =>
        PlatformOf(
            OperatingSystem.IsWindows() ? "win" : OperatingSystem.IsMacOS() ? "osx" : OperatingSystem.IsLinux() ? "linux" : null,
            RuntimeInformation.ProcessArchitecture);

    public static string? PlatformOf(string? os, Architecture architecture) =>
        os is null ? null : architecture switch
        {
            Architecture.X64 => os + "-x64",
            Architecture.Arm64 => os + "-arm64",
            _ => null,
        };

    /// <returns>The full path, or null if there is none. Throws if an explicit choice does not exist.</returns>
    public static string? Find(string? explicitPath, string workingDirectory, Func<string, string?> getEnvironmentVariable, string baseDirectory, string? platform = null)
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

        if (File.Exists(sibling))
        {
            return sibling;
        }

        string? rid = platform ?? CurrentPlatform();

        if (rid is null)
        {
            return null;
        }

        string bundled = Path.Combine(baseDirectory, "analyzers", rid, ExecutableName);

        if (!File.Exists(bundled))
        {
            return null;
        }

        EnsureExecutable(bundled);
        return bundled;
    }

    /// <summary>
    /// NuGet does not keep the execute permission of the files in a package, so the bundled analyzer is made executable the first time it
    /// is used. Only the analyzer that came with the tool is touched: a path the user named is theirs to set up.
    /// </summary>
    private static void EnsureExecutable(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        UnixFileMode mode = File.GetUnixFileMode(path);
        UnixFileMode needed = UnixFileMode.UserExecute;

        if (mode.HasFlag(UnixFileMode.GroupRead))
        {
            needed |= UnixFileMode.GroupExecute;
        }

        if (mode.HasFlag(UnixFileMode.OtherRead))
        {
            needed |= UnixFileMode.OtherExecute;
        }

        if ((mode & needed) == needed)
        {
            return;
        }

        try
        {
            File.SetUnixFileMode(path, mode | needed);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InvalidInputException(
                $"the analyzer that came with deprisk is not executable and could not be made executable ({ex.Message}); run: chmod +x {SafeText.Clean(path, 200)}");
        }
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
        "reachability analysis needs the analyzer (" + ExecutableName + "). The NuGet package bundles it for "
        + string.Join(", ", BundledPlatforms) + $" (this machine: {CurrentPlatform() ?? "not one of them"}). "
        + "Otherwise build it with 'cargo build --release --locked' in analyzers/reach "
        + $"and pass --analyzer <path>, set {EnvironmentVariable}, or put it next to the deprisk executable. "
        + "(deprisk does not search PATH for it.) See docs/adr/0013-reach-command.md and docs/adr/0022-analyzer-distribution.md.";
}
