using System.Runtime.InteropServices;
using DepRisk.Data.Reach;
using Xunit;

namespace DepRisk.Data.Tests;

/// <summary>The analyzer that the NuGet package bundles next to the tool, analyzers/&lt;platform&gt;/ (ADR 0022).</summary>
public sealed class AnalyzerLocatorBundledTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-bundled-" + Guid.NewGuid().ToString("N"));

    public AnalyzerLocatorBundledTests() => Directory.CreateDirectory(_root);

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private string Base => Path.Combine(_root, "tool");

    private string Bundled(string platform, UnixFileMode? mode = null)
    {
        string dir = Path.Combine(Base, "analyzers", platform);
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, AnalyzerLocator.ExecutableName);
        File.WriteAllText(path, "x");

        if (mode is { } m && !OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, m);
        }

        return path;
    }

    private static string? NoEnvironment(string name) => null;

    [Fact]
    public void The_analyzer_bundled_for_this_platform_is_found_when_nothing_else_is_given()
    {
        string bundled = Bundled("linux-x64");
        Bundled("osx-arm64");

        Assert.Equal(bundled, AnalyzerLocator.Find(null, _root, NoEnvironment, Base, "linux-x64"));
        Assert.Contains("osx-arm64", AnalyzerLocator.Find(null, _root, NoEnvironment, Base, "osx-arm64")!);
    }

    [Fact]
    public void An_analyzer_for_another_platform_is_not_used()
    {
        Bundled("osx-arm64");

        Assert.Null(AnalyzerLocator.Find(null, _root, NoEnvironment, Base, "linux-x64"));
    }

    [Fact]
    public void An_explicit_choice_the_environment_and_a_sibling_all_win_over_the_bundled_analyzer()
    {
        string bundled = Bundled("linux-x64");
        string explicitPath = Path.Combine(_root, "mine");
        File.WriteAllText(explicitPath, "x");
        string env = Path.Combine(_root, "fromenv");
        File.WriteAllText(env, "x");

        Assert.Equal(explicitPath, AnalyzerLocator.Find(explicitPath, _root, NoEnvironment, Base, "linux-x64"));
        Assert.Equal(env, AnalyzerLocator.Find(null, _root, name => name == AnalyzerLocator.EnvironmentVariable ? env : null, Base, "linux-x64"));

        string sibling = Path.Combine(Base, AnalyzerLocator.ExecutableName);
        File.WriteAllText(sibling, "x");
        Assert.Equal(sibling, AnalyzerLocator.Find(null, _root, NoEnvironment, Base, "linux-x64"));
        Assert.NotEqual(bundled, sibling);
    }

    [Fact]
    public void The_path_variable_is_still_never_searched_and_a_platform_that_is_unknown_finds_nothing()
    {
        Bundled("linux-x64");

        Assert.Null(AnalyzerLocator.Find(null, _root, name => name == "PATH" ? Path.Combine(Base, "analyzers", "linux-x64") : null, Path.Combine(_root, "empty"), "linux-x64"));
        Assert.Null(AnalyzerLocator.PlatformOf(null, Architecture.X64));
    }

    [Theory]
    [InlineData("linux", Architecture.X64, "linux-x64")]
    [InlineData("linux", Architecture.Arm64, "linux-arm64")]
    [InlineData("osx", Architecture.X64, "osx-x64")]
    [InlineData("osx", Architecture.Arm64, "osx-arm64")]
    [InlineData("win", Architecture.X64, "win-x64")]
    public void The_platform_name_is_the_operating_system_and_the_architecture(string os, Architecture architecture, string expected)
    {
        Assert.Equal(expected, AnalyzerLocator.PlatformOf(os, architecture));
        Assert.Contains(expected, AnalyzerLocator.BundledPlatforms);
    }

    [Theory]
    [InlineData("linux", Architecture.X86)]
    [InlineData("linux", Architecture.Arm)]
    [InlineData("win", Architecture.Wasm)]
    [InlineData("osx", Architecture.S390x)]
    public void An_architecture_that_is_not_x64_or_arm64_has_no_platform(string os, Architecture architecture)
    {
        Assert.Null(AnalyzerLocator.PlatformOf(os, architecture));
    }

    [Fact]
    public void The_bundled_analyzer_is_made_executable_for_those_who_can_read_it_and_only_that_one()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        // NuGet does not keep the execute permission of the files in a package.
        string worldReadable = Bundled("linux-x64", UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        AnalyzerLocator.Find(null, _root, NoEnvironment, Base, "linux-x64");
        Assert.Equal(
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute,
            File.GetUnixFileMode(worldReadable));

        // Nobody is given execute permission they could not read the file with.
        string privateFile = Bundled("osx-arm64", UnixFileMode.UserRead | UnixFileMode.UserWrite);
        AnalyzerLocator.Find(null, _root, NoEnvironment, Base, "osx-arm64");
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(privateFile));

        string groupReadable = Bundled("osx-x64", UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
        AnalyzerLocator.Find(null, _root, NoEnvironment, Base, "osx-x64");
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute, File.GetUnixFileMode(groupReadable));
    }

    [Fact]
    public void A_file_the_user_named_is_never_changed()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        string mine = Path.Combine(_root, "mine");
        File.WriteAllText(mine, "x");
        UnixFileMode before = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;
        File.SetUnixFileMode(mine, before);

        AnalyzerLocator.Find(mine, _root, NoEnvironment, Base, "linux-x64");
        AnalyzerLocator.Find(null, _root, name => name == AnalyzerLocator.EnvironmentVariable ? mine : null, Base, "linux-x64");

        Assert.Equal(before, File.GetUnixFileMode(mine));
    }

    [Fact]
    public void An_analyzer_that_is_already_executable_is_left_alone()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        UnixFileMode mode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        string path = Bundled("linux-x64", mode);

        AnalyzerLocator.Find(null, _root, NoEnvironment, Base, "linux-x64");

        Assert.Equal(mode, File.GetUnixFileMode(path));
    }

    [Fact]
    public void The_message_when_there_is_no_analyzer_says_where_it_comes_from_and_what_to_do()
    {
        string message = AnalyzerLocator.NotFoundMessage();

        Assert.Contains("linux-x64", message);
        Assert.Contains("win-x64", message);
        Assert.Contains("cargo build --release --locked", message);
        Assert.Contains("--analyzer", message);
        Assert.Contains(AnalyzerLocator.EnvironmentVariable, message);
        Assert.Contains("does not search PATH", message);
    }
}
