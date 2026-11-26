using System.Text;
using System.Text.RegularExpressions;
using Xunit;

namespace DepRisk.Cli.Tests;

/// <summary>
/// The reachability analyzer is built with one Rust release, named in analyzers/reach/rust-toolchain.toml and installed by every workflow
/// (S27, ADR 0031). These tests read the repository's own files and fail when a workflow goes back to a floating toolchain, when the pin is
/// not an exact release, or when it falls below the crate's own minimum.
/// </summary>
public sealed partial class RustToolchainPinTests
{
    private static string ReadRepoFile(string relative) =>
        File.ReadAllText(Path.Combine(DocsConsistencyTests.Root(), relative.Replace('/', Path.DirectorySeparatorChar)), Encoding.UTF8).Replace("\r\n", "\n");

    private static string PinnedChannel()
    {
        Match match = ChannelLine().Match(ReadRepoFile("analyzers/reach/rust-toolchain.toml"));
        Assert.True(match.Success, "analyzers/reach/rust-toolchain.toml has no 'channel = \"...\"' line");
        return match.Groups[1].Value;
    }

    /// <summary>The non-comment lines of every workflow file, with the file name.</summary>
    private static List<(string File, int Line, string Text)> WorkflowLines()
    {
        string directory = Path.Combine(DocsConsistencyTests.Root(), ".github", "workflows");
        List<(string, int, string)> lines = [];

        foreach (string file in Directory.GetFiles(directory, "*.yml").OrderBy(f => f, StringComparer.Ordinal))
        {
            string[] all = File.ReadAllText(file, Encoding.UTF8).Replace("\r\n", "\n").Split('\n');

            for (int i = 0; i < all.Length; i++)
            {
                if (!all[i].TrimStart().StartsWith('#'))
                {
                    lines.Add((Path.GetFileName(file), i + 1, all[i]));
                }
            }
        }

        Assert.NotEmpty(lines);
        return lines;
    }

    [Fact]
    public void The_pin_is_one_exact_release_and_not_a_channel()
    {
        string channel = PinnedChannel();

        Assert.True(ExactRelease().IsMatch(channel), $"the pin '{channel}' is not an exact release such as 1.89.0 (a channel name floats)");
    }

    [Fact]
    public void The_pin_installs_the_components_the_lint_and_format_steps_need_and_nothing_more()
    {
        string file = ReadRepoFile("analyzers/reach/rust-toolchain.toml");

        Assert.Contains("profile = \"minimal\"", file);
        Assert.Contains("\"clippy\"", file);
        Assert.Contains("\"rustfmt\"", file);
    }

    [Fact]
    public void The_pinned_release_is_not_older_than_the_rust_version_of_the_crate()
    {
        Match required = RustVersionLine().Match(ReadRepoFile("analyzers/reach/Cargo.toml"));
        Assert.True(required.Success, "analyzers/reach/Cargo.toml has no rust-version");

        Version minimum = Version.Parse(required.Groups[1].Value.Count(c => c == '.') == 1 ? required.Groups[1].Value + ".0" : required.Groups[1].Value);
        Assert.True(Version.TryParse(PinnedChannel(), out Version? pinned), $"the pin '{PinnedChannel()}' is not a release number");

        Assert.True(pinned >= minimum, $"the pinned release {pinned} is older than the crate's rust-version {minimum}");
    }

    [Fact]
    public void No_workflow_names_a_floating_toolchain_or_a_version_of_its_own()
    {
        foreach ((string file, int line, string text) in WorkflowLines())
        {
            if (!text.Contains("rustup", StringComparison.Ordinal) && !text.Contains("dtolnay", StringComparison.Ordinal) && !text.Contains("rust-toolchain@", StringComparison.Ordinal))
            {
                continue;
            }

            // The only rustup command a workflow may run to get a compiler is the one with no argument: it reads the pin.
            bool installFromFile = InstallFromFile().IsMatch(text);
            bool showActive = text.Trim() == "rustup show active-toolchain";
            bool addTarget = AddTarget().IsMatch(text); // a target of the pinned toolchain (the static musl analyzer), not another toolchain

            Assert.True(installFromFile || showActive || addTarget, $"{file}:{line}: '{text.Trim()}' names a toolchain other than the pinned one (use 'rustup toolchain install', which reads analyzers/reach/rust-toolchain.toml)");
        }
    }

    [Fact]
    public void Every_job_that_runs_cargo_installs_the_pinned_toolchain_before_it()
    {
        foreach (IGrouping<string, (string File, int Line, string Text)> workflow in WorkflowLines().GroupBy(l => l.File))
        {
            bool installed = false;

            foreach ((string file, int line, string text) in workflow)
            {
                if (JobHeader().IsMatch(text))
                {
                    installed = false; // a job is a fresh runner
                }
                else if (InstallFromFile().IsMatch(text))
                {
                    installed = true;
                }
                else if (CargoCommand().IsMatch(text))
                {
                    Assert.True(installed, $"{file}:{line}: '{text.Trim()}' runs cargo in a job that has not installed the pinned toolchain before it");
                }
            }
        }
    }

    [Fact]
    public void The_workflows_that_build_the_analyzer_are_the_ones_the_test_looks_at()
    {
        // Guard against the test passing because it found nothing: the build and CI workflows do run cargo today.
        List<string> withCargo = WorkflowLines().Where(l => CargoCommand().IsMatch(l.Text)).Select(l => l.File).Distinct().ToList();

        Assert.Contains("analyzer-build.yml", withCargo);
        Assert.Contains("ci.yml", withCargo);
    }

    [GeneratedRegex(@"^channel\s*=\s*""([^""]+)""\s*$", RegexOptions.Multiline)]
    private static partial Regex ChannelLine();

    [GeneratedRegex(@"^rust-version\s*=\s*""([0-9.]+)""\s*$", RegexOptions.Multiline)]
    private static partial Regex RustVersionLine();

    [GeneratedRegex(@"^\d+\.\d+\.\d+$")]
    private static partial Regex ExactRelease();

    [GeneratedRegex(@"(^|[\s:|])rustup toolchain install\s*$")]
    private static partial Regex InstallFromFile();

    [GeneratedRegex(@"^\s*rustup target add [a-z0-9_]+(-[a-z0-9_]+)+\s*$")]
    private static partial Regex AddTarget();

    [GeneratedRegex(@"^  [A-Za-z0-9_-]+:\s*$")]
    private static partial Regex JobHeader();

    [GeneratedRegex(@"(^|[\s:|])cargo\s+(build|test|clippy|fmt|run|check)\b")]
    private static partial Regex CargoCommand();
}
