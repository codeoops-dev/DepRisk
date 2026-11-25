using System.Text;
using System.Text.RegularExpressions;
using Xunit;

namespace DepRisk.Cli.Tests;

/// <summary>
/// The README and the docs must keep up with the code (S22). These tests read the repository's own documents and fail when the command list,
/// the status legend, a link, an ADR reference or a design-only section drifts from what is built. They need the repository root: it is found
/// by walking up from the test binaries, or from the environment variable DEPRISK_REPO_ROOT.
/// </summary>
public sealed partial class DocsConsistencyTests
{
    private static readonly string[] Statuses = ["✅", "🧪", "🚧", "🗺️"];

    internal static string Root()
    {
        string? fromEnvironment = Environment.GetEnvironmentVariable("DEPRISK_REPO_ROOT");

        if (!string.IsNullOrEmpty(fromEnvironment) && File.Exists(Path.Combine(fromEnvironment, "README.md")))
        {
            return fromEnvironment;
        }

        for (DirectoryInfo? dir = new(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "README.md")) && File.Exists(Path.Combine(dir.FullName, "DepRisk.slnx")))
            {
                return dir.FullName;
            }
        }

        throw new InvalidOperationException("The repository root was not found (README.md next to DepRisk.slnx). Set DEPRISK_REPO_ROOT.");
    }

    private static string Read(string relative) => File.ReadAllText(Path.Combine(Root(), relative.Replace('/', Path.DirectorySeparatorChar)), Encoding.UTF8).Replace("\r\n", "\n");

    private static string Section(string markdown, string heading)
    {
        int start = markdown.IndexOf("\n## " + heading + "\n", StringComparison.Ordinal);
        Assert.True(start >= 0, $"README has no '## {heading}' section");
        int next = markdown.IndexOf("\n## ", start + 4, StringComparison.Ordinal);
        return next < 0 ? markdown[start..] : markdown[start..next];
    }

    /// <summary>The commands named in <c>deprisk --help</c>, for example "init", "symbols check", "vex verify".</summary>
    private static List<string> CommandsInHelp()
    {
        using StringWriter output = new();
        using StringWriter error = new();
        int code = CliApp.Run(["--help"], output, error, TestContext.For(Path.GetTempPath()));
        Assert.Equal(0, code);

        List<string> commands = [];
        bool inCommands = false;

        foreach (string line in output.ToString().Replace("\r\n", "\n").Split('\n'))
        {
            if (line == "Commands:")
            {
                inCommands = true;
                continue;
            }

            if (!inCommands)
            {
                continue;
            }

            if (line.Length == 0)
            {
                break;
            }

            // A command starts exactly two spaces in; option lines are indented further.
            if (line.StartsWith("  ", StringComparison.Ordinal) && !line.StartsWith("   ", StringComparison.Ordinal))
            {
                List<string> words = [];

                foreach (string word in line.TrimStart().Split(' ', StringSplitOptions.RemoveEmptyEntries))
                {
                    if (word.StartsWith('[') || word.StartsWith('<') || word.StartsWith('-'))
                    {
                        break;
                    }

                    words.Add(word);

                    // Two-word commands are written "name sub"; a description starts after two spaces, which Split removed, so stop at the known shapes.
                    if (words.Count == 2 || !IsCommandPrefix(words[0]))
                    {
                        break;
                    }
                }

                commands.Add(string.Join(' ', words));
            }
        }

        return commands;
    }

    private static bool IsCommandPrefix(string word) => word is "symbols" or "vex" or "bench" or "audit";

    [Fact]
    public void Every_command_in_the_help_text_is_in_the_readme_usage_table()
    {
        string usage = Section(Read("README.md"), "Usage");
        List<string> commands = CommandsInHelp();

        Assert.Contains("init", commands);
        Assert.Contains("symbols check", commands);
        Assert.Contains("audit verify", commands);

        foreach (string command in commands)
        {
            Assert.True(
                usage.Contains($"`deprisk {command} ", StringComparison.Ordinal) || usage.Contains($"`deprisk {command}`", StringComparison.Ordinal) || usage.Contains($"`deprisk {command}\\|", StringComparison.Ordinal),
                $"the README Usage table has no row for 'deprisk {command}'");
        }
    }

    [Fact]
    public void Every_feature_status_row_has_one_of_the_four_marks_and_the_legend_names_them()
    {
        string status = Section(Read("README.md"), "Feature status");
        string legend = status.Split('\n').First(l => l.StartsWith("Legend:", StringComparison.Ordinal));

        foreach (string mark in Statuses)
        {
            Assert.Contains(mark, legend);
        }

        List<string> rows = status.Split('\n').Where(l => l.StartsWith("| ", StringComparison.Ordinal) && !l.StartsWith("| Area ", StringComparison.Ordinal) && !l.StartsWith("|---", StringComparison.Ordinal)).ToList();

        Assert.True(rows.Count > 20, "the Feature status table has too few rows");

        foreach (string row in rows)
        {
            string last = row.TrimEnd().TrimEnd('|').Trim().Split('|').Last().Trim();
            Assert.True(Statuses.Contains(last), $"a Feature status row does not end in one of the four marks: {row[..Math.Min(row.Length, 90)]}");
        }
    }

    [Fact]
    public void A_command_cannot_be_both_built_and_listed_as_planned_in_the_usage_table()
    {
        string usage = Section(Read("README.md"), "Usage");
        List<string> commands = CommandsInHelp();

        foreach (string row in usage.Split('\n').Where(r => r.Contains("*(planned)*", StringComparison.Ordinal)))
        {
            foreach (string command in commands)
            {
                Assert.False(row.StartsWith($"| `deprisk {command} ", StringComparison.Ordinal) || row.StartsWith($"| `deprisk {command}`", StringComparison.Ordinal), $"'deprisk {command}' exists but its Usage row says planned");
            }
        }
    }

    [Theory]
    [InlineData("Configuration")]
    [InlineData("Air-gapped operation")]
    public void Sections_that_describe_unbuilt_behavior_say_so_at_the_top(string heading)
    {
        string section = Section(Read("README.md"), heading);
        string firstLines = string.Join('\n', section.Split('\n').Skip(1).Take(4));

        Assert.True(firstLines.Contains("lanned", StringComparison.Ordinal), $"the '{heading}' section does not say at its top that it is (partly) planned");
    }

    [Fact]
    public void The_readme_no_longer_makes_claims_that_were_found_to_be_stale()
    {
        string readme = Read("README.md");

        foreach (string stale in new[]
        {
            "the CLI is currently the only binary",
            "it is not in the NuGet package yet",
            "deprisk vex --status",
            "Probability quantiles do not exist yet",
            "deprisk bench --suite quick     #",
        })
        {
            Assert.DoesNotContain(stale, readme);
        }
    }

    [Fact]
    public void Every_relative_link_in_the_readme_and_the_docs_points_to_something_that_exists()
    {
        string root = Root();
        List<string> files = ["README.md", "CONTRIBUTING.md", "SECURITY.md", .. Directory.GetFiles(Path.Combine(root, "docs"), "*.md", SearchOption.AllDirectories).Select(f => Path.GetRelativePath(root, f).Replace('\\', '/'))];
        List<string> problems = [];

        foreach (string file in files)
        {
            string text = Read(file);
            string baseDir = Path.GetDirectoryName(Path.Combine(root, file.Replace('/', Path.DirectorySeparatorChar)))!;

            // Links inside code fences are examples, not links.
            string withoutCode = FencedCode().Replace(text, string.Empty);

            foreach (Match match in LinkPattern().Matches(withoutCode))
            {
                string target = match.Groups[1].Value;

                if (target.StartsWith("http://", StringComparison.Ordinal) || target.StartsWith("https://", StringComparison.Ordinal) || target.StartsWith("mailto:", StringComparison.Ordinal))
                {
                    continue;
                }

                string path = target;
                string? anchor = null;
                int hash = target.IndexOf('#', StringComparison.Ordinal);

                if (hash >= 0)
                {
                    path = target[..hash];
                    anchor = target[(hash + 1)..];
                }

                string full = path.Length == 0 ? Path.Combine(root, file.Replace('/', Path.DirectorySeparatorChar)) : Path.GetFullPath(Path.Combine(baseDir, path));

                if (!File.Exists(full) && !Directory.Exists(full))
                {
                    problems.Add($"{file}: '{target}' does not exist");
                    continue;
                }

                if (anchor is { Length: > 0 } && full.EndsWith(".md", StringComparison.Ordinal) && !Headings(File.ReadAllText(full, Encoding.UTF8).Replace("\r\n", "\n")).Contains(anchor))
                {
                    problems.Add($"{file}: '{target}' has no such heading");
                }
            }
        }

        Assert.True(problems.Count == 0, string.Join("\n", problems));
    }

    [Fact]
    public void Every_adr_named_in_the_readme_exists_and_every_adr_file_has_the_title_of_its_number()
    {
        string root = Root();
        string adrDir = Path.Combine(root, "docs", "adr");
        string[] adrFiles = Directory.GetFiles(adrDir, "*.md");
        HashSet<string> numbers = adrFiles.Select(f => Path.GetFileName(f)[..4]).ToHashSet(StringComparer.Ordinal);

        Assert.True(numbers.Count >= 26);

        foreach (string file in adrFiles)
        {
            string name = Path.GetFileName(file);
            string firstLine = File.ReadLines(file).First().Trim();

            Assert.True(firstLine.StartsWith($"# ADR {name[..4]}:", StringComparison.Ordinal), $"{name}: the first line is '{firstLine}'");
        }

        foreach (Match match in AdrReference().Matches(Read("README.md")))
        {
            Assert.True(numbers.Contains(match.Groups[1].Value), $"the README names ADR {match.Groups[1].Value}, which does not exist");
        }

        for (int n = 1; n <= numbers.Count; n++)
        {
            Assert.True(numbers.Contains(n.ToString("D4")), $"ADR numbers have a gap at {n:D4}");
        }
    }

    [Fact]
    public void The_ci_help_names_every_term_the_policy_gate_accepts()
    {
        using StringWriter output = new();
        using StringWriter error = new();
        Assert.Equal(0, CliApp.Run(["--help"], output, error, TestContext.For(Path.GetTempPath())));
        string help = output.ToString();

        foreach (string term in new[] { "any", "kev", "ransomware", "direct", "fixable", "cvss>=N", "epss>=P", "severity>=LEVEL", "reachable", "possibly-reachable", "reach-unknown", "unreachable", "not-unreachable" })
        {
            Assert.Contains(term, help);
        }
    }

    [Fact]
    public void The_roadmap_page_exists_and_the_contributor_checklist_asks_for_the_sweep()
    {
        Assert.Contains("v0.2 code-complete", Read("docs/roadmap.md"));
        Assert.Contains("Sweep the whole README", Read("CONTRIBUTING.md"));
    }

    private static HashSet<string> Headings(string markdown)
    {
        HashSet<string> slugs = new(StringComparer.Ordinal);
        bool fenced = false;

        foreach (string line in markdown.Split('\n'))
        {
            if (line.StartsWith("```", StringComparison.Ordinal))
            {
                fenced = !fenced;
                continue;
            }

            if (fenced || !line.StartsWith('#'))
            {
                continue;
            }

            string title = line.TrimStart('#').Trim();
            StringBuilder slug = new();

            foreach (char c in title.ToLowerInvariant())
            {
                if (char.IsLetterOrDigit(c) || c is '-' or '_')
                {
                    slug.Append(c);
                }
                else if (c == ' ')
                {
                    slug.Append('-');
                }
            }

            slugs.Add(slug.ToString());
        }

        return slugs;
    }

    [GeneratedRegex(@"\]\(([^)\s]+)\)")]
    private static partial Regex LinkPattern();

    [GeneratedRegex(@"```.*?```", RegexOptions.Singleline)]
    private static partial Regex FencedCode();

    [GeneratedRegex(@"ADR (\d{4})")]
    private static partial Regex AdrReference();
}
