using DepRisk.Core;
using DepRisk.Data.Reach;
using Xunit;

namespace DepRisk.Data.Tests;

public sealed class AnalyzerLocatorTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-locator-" + Guid.NewGuid().ToString("N"));

    public AnalyzerLocatorTests() => Directory.CreateDirectory(_root);

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private string Exe(string directory, string name)
    {
        string dir = Path.Combine(_root, directory);
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, name);
        File.WriteAllText(path, "x");
        return path;
    }

    private static string? NoEnvironment(string name) => null;

    [Fact]
    public void An_explicit_path_wins_over_the_environment_and_the_sibling()
    {
        string explicitPath = Exe("a", "mine");
        Exe("base", AnalyzerLocator.ExecutableName);
        string env = Exe("env", "fromenv");

        string? found = AnalyzerLocator.Find(explicitPath, _root, name => name == AnalyzerLocator.EnvironmentVariable ? env : null, Path.Combine(_root, "base"));

        Assert.Equal(explicitPath, found);
    }

    [Fact]
    public void The_environment_variable_wins_over_the_sibling_and_a_relative_path_is_relative_to_the_working_directory()
    {
        Exe("base", AnalyzerLocator.ExecutableName);
        string env = Exe("env", "fromenv");

        Assert.Equal(env, AnalyzerLocator.Find(null, _root, name => name == AnalyzerLocator.EnvironmentVariable ? "env/fromenv" : null, Path.Combine(_root, "base")));
    }

    [Fact]
    public void The_sibling_of_the_cli_is_the_last_resort_and_nothing_found_is_null()
    {
        string sibling = Exe("base", AnalyzerLocator.ExecutableName);

        Assert.Equal(sibling, AnalyzerLocator.Find(null, _root, NoEnvironment, Path.Combine(_root, "base")));
        Assert.Null(AnalyzerLocator.Find(null, _root, NoEnvironment, Path.Combine(_root, "empty")));
    }

    [Fact]
    public void An_explicit_choice_that_does_not_exist_is_an_error_not_a_fallback()
    {
        Exe("base", AnalyzerLocator.ExecutableName);

        Assert.Contains("--analyzer", Assert.Throws<InvalidInputException>(() => AnalyzerLocator.Find("nope", _root, NoEnvironment, Path.Combine(_root, "base"))).Message);
        Assert.Contains("DEPRISK_REACH", Assert.Throws<InvalidInputException>(() => AnalyzerLocator.Find(null, _root, _ => "nope", Path.Combine(_root, "base"))).Message);
    }

    [Fact]
    public void The_path_variable_is_never_searched()
    {
        string onPath = Exe("onpath", AnalyzerLocator.ExecutableName);

        string? found = AnalyzerLocator.Find(null, _root, name => name == "PATH" ? Path.GetDirectoryName(onPath) : null, Path.Combine(_root, "empty"));

        Assert.Null(found);
        Assert.Contains("does not search PATH", AnalyzerLocator.NotFoundMessage());
    }
}
