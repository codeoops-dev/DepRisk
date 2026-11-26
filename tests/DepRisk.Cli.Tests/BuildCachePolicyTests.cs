using System.Text;
using System.Text.RegularExpressions;
using Xunit;

namespace DepRisk.Cli.Tests;

/// <summary>
/// CI reuses compiled dependencies to stay fast (S27b, ADR 0032), but a release is always built from scratch. These tests read the
/// workflow files and fail when a cache can reach a release build.
/// </summary>
public sealed partial class BuildCachePolicyTests
{
    private static string Workflow(string name) =>
        File.ReadAllText(Path.Combine(DocsConsistencyTests.Root(), ".github", "workflows", name), Encoding.UTF8).Replace("\r\n", "\n");

    [Fact]
    public void The_cache_input_of_the_analyzer_build_is_off_unless_a_caller_turns_it_on()
    {
        string text = Workflow("analyzer-build.yml");

        string[] lines = text.Split('\n');
        int input = Array.FindIndex(lines, l => l == "      cache:");

        Assert.True(input >= 0, "analyzer-build.yml must declare the input 'cache'");

        // The input's own lines are the more deeply indented ones that follow it.
        List<string> body = lines.Skip(input + 1).TakeWhile(l => l.StartsWith("        ", StringComparison.Ordinal)).Select(l => l.Trim()).ToList();

        Assert.Contains("default: false", body);
    }

    [Fact]
    public void Every_cache_step_of_the_analyzer_build_runs_only_when_the_input_is_true()
    {
        string[] lines = Workflow("analyzer-build.yml").Split('\n');
        int found = 0;

        for (int i = 0; i < lines.Length; i++)
        {
            if (!lines[i].Contains("uses: actions/cache@", StringComparison.Ordinal))
            {
                continue;
            }

            found++;
            int start = i;
            while (start > 0 && !lines[start].StartsWith("      - ", StringComparison.Ordinal))
            {
                start--;
            }

            int end = i + 1;
            while (end < lines.Length && !lines[end].StartsWith("      - ", StringComparison.Ordinal))
            {
                end++;
            }

            bool guarded = lines[start..end].Any(l => l.Trim() is "if: inputs.cache" or "- if: inputs.cache");
            Assert.True(guarded, $"analyzer-build.yml line {i + 1}: a cache step without 'if: inputs.cache'");
        }

        Assert.True(found >= 1, "the analyzer build has no cache step (the policy test found nothing to check)");
    }

    [Theory]
    [InlineData("release.yml")]
    [InlineData("package.yml")]
    public void The_release_path_has_no_cache_of_its_own(string file)
    {
        string text = Workflow(file);

        Assert.DoesNotContain("actions/cache", text);
        Assert.DoesNotContain("cache: true", text);
    }

    [Fact]
    public void The_release_builds_the_analyzers_without_asking_for_a_cache()
    {
        string text = Workflow("release.yml");
        Match job = AnalyzersJob().Match(text);

        Assert.True(job.Success, "release.yml has no 'analyzers' job that calls analyzer-build.yml");
        Assert.DoesNotContain("cache:", job.Value);
    }

    [Fact]
    public void Ci_asks_for_the_cache()
    {
        Match job = AnalyzersJob().Match(Workflow("ci.yml"));

        Assert.True(job.Success, "ci.yml has no 'analyzers' job that calls analyzer-build.yml");
        Assert.Contains("cache: true", job.Value);
    }

    [GeneratedRegex(@"^  analyzers:\n(    [^\n]*\n|\n)+", RegexOptions.Multiline)]
    private static partial Regex AnalyzersJob();
}
