using System.Text;
using System.Text.RegularExpressions;
using DepRisk.Data.Reach;
using Xunit;

namespace DepRisk.Cli.Tests;

/// <summary>
/// The list of platforms the analyzer is bundled for lives in six places (the locator, the project file, the package workflow, the package
/// check, the analyzer build matrix, the package readme). A platform added in one and forgotten in another is a package that fails at
/// release or a user who is told the wrong thing; these tests make the lists agree (ADR 0033).
/// </summary>
public sealed partial class BundledPlatformsAgreeTests
{
    private static string Read(string relative) =>
        File.ReadAllText(Path.Combine(DocsConsistencyTests.Root(), relative.Replace('/', Path.DirectorySeparatorChar)), Encoding.UTF8).Replace("\r\n", "\n");

    private static List<string> Expected() => AnalyzerLocator.BundledPlatforms.OrderBy(p => p, StringComparer.Ordinal).ToList();

    private static List<string> Sorted(IEnumerable<string> platforms) => platforms.OrderBy(p => p, StringComparer.Ordinal).ToList();

    private static void AssertSame(string where, IEnumerable<string> actual)
    {
        List<string> expected = Expected();
        List<string> found = Sorted(actual);

        Assert.True(expected.SequenceEqual(found), $"{where} lists [{string.Join(", ", found)}] but AnalyzerLocator.BundledPlatforms is [{string.Join(", ", expected)}]");
    }

    [Fact]
    public void The_project_file_bundles_the_same_platforms()
    {
        Match match = ProjectList().Match(Read("src/DepRisk.Cli/DepRisk.Cli.csproj"));
        Assert.True(match.Success, "DepRisk.Cli.csproj has no BundledAnalyzerPlatforms");

        AssertSame("BundledAnalyzerPlatforms in DepRisk.Cli.csproj", match.Groups[1].Value.Split(';', StringSplitOptions.RemoveEmptyEntries));
    }

    [Fact]
    public void The_package_check_requires_the_same_platforms()
    {
        Match match = PythonList().Match(Read("build/verify-package.py"));
        Assert.True(match.Success, "verify-package.py has no PLATFORMS list");

        AssertSame("PLATFORMS in build/verify-package.py", Quoted().Matches(match.Groups[1].Value).Select(m => m.Groups[1].Value));
    }

    [Fact]
    public void The_package_workflow_stages_the_same_platforms()
    {
        Match match = StagingLoop().Match(Read(".github/workflows/package.yml"));
        Assert.True(match.Success, "package.yml has no 'for rid in ...' loop");

        AssertSame("the staging loop in package.yml", match.Groups[1].Value.Split(' ', StringSplitOptions.RemoveEmptyEntries));
    }

    [Fact]
    public void The_analyzer_build_makes_the_same_platforms_and_each_one_once()
    {
        List<string> rids = MatrixRid().Matches(Read(".github/workflows/analyzer-build.yml")).Select(m => m.Groups[1].Value).ToList();

        Assert.Equal(rids.Count, rids.Distinct().Count());
        AssertSame("the matrix in analyzer-build.yml", rids);
    }

    [Fact]
    public void The_package_readme_names_every_platform()
    {
        string readme = Read("src/DepRisk.Cli/PACKAGE.md");

        foreach (string platform in AnalyzerLocator.BundledPlatforms)
        {
            Assert.True(readme.Contains(platform, StringComparison.Ordinal), $"src/DepRisk.Cli/PACKAGE.md does not name {platform}");
        }
    }

    [GeneratedRegex(@"<BundledAnalyzerPlatforms>([^<]+)</BundledAnalyzerPlatforms>")]
    private static partial Regex ProjectList();

    [GeneratedRegex(@"^PLATFORMS = \[([^\]]+)\]", RegexOptions.Multiline)]
    private static partial Regex PythonList();

    [GeneratedRegex(@"""([a-z0-9-]+)""")]
    private static partial Regex Quoted();

    [GeneratedRegex(@"for rid in ([a-z0-9 -]+); do")]
    private static partial Regex StagingLoop();

    [GeneratedRegex(@"^\s+- \{ rid: ([a-z0-9-]+),", RegexOptions.Multiline)]
    private static partial Regex MatrixRid();
}
