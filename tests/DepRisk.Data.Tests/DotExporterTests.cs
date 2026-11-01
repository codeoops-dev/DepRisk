using DepRisk.Core.Hypergraph;
using DepRisk.Core.Model;
using DepRisk.Data.Hypergraph;
using Xunit;

namespace DepRisk.Data.Tests;

public class DotExporterTests
{
    private static ResolvedPackage Pkg(string id, string version, bool direct = false, string? requested = null, params (string Id, string Range)[] deps) =>
        new(id, version, direct, deps.Select(d => new DependencyRef(d.Id, d.Range)).ToList(), requested);

    private static HypergraphResult Result(params TargetGraph[] targets) =>
        HypergraphBuilder.Build(new ScanResult(1, new ToolInfo("deprisk", "0.0.0-test"), "nuget", [new ProjectGraph("App", "obj/project.assets.json", targets)]));

    private static HypergraphResult Sample() =>
        Result(new TargetGraph(
            "net10.0",
            [
                Pkg("Lib.A", "1.0.0", true, ">= 1.0.0", ("Lib.B", "[1.0.0, 1.2.0)"), ("Lib.Missing", "1.0.0"), ("Lib.C", "2.0.0")),
                Pkg("Lib.B", "1.5.0"),
                Pkg("Lib.C", "2.1.0"),
            ]));

    /// <summary>True if every double-quoted string on every line is properly closed, honouring backslash escapes.</summary>
    private static bool QuotesAreBalanced(string dot)
    {
        foreach (string line in dot.Split('\n'))
        {
            bool inString = false;

            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];

                if (inString && c == '\\')
                {
                    i++;
                }
                else if (c == '"')
                {
                    inString = !inString;
                }
            }

            if (inString)
            {
                return false;
            }
        }

        return true;
    }

    [Fact]
    public void The_document_is_a_digraph_with_one_cluster_per_target_and_labelled_nodes()
    {
        string dot = DotExporter.Export(Sample());

        Assert.StartsWith("digraph deprisk {", dot);
        Assert.EndsWith("}\n", dot);
        Assert.Contains("subgraph \"cluster_0\"", dot);
        Assert.Contains("label=\"App (net10.0)\"", dot);
        Assert.Contains("[label=\"Lib.A 1.0.0\", style=filled", dot);
        Assert.Contains("[label=\"Lib.B 1.5.0\"]", dot);
        Assert.Contains("shape=house", dot);
        Assert.Contains("shape=point", dot);
    }

    [Fact]
    public void Violated_requirements_are_red_and_undecided_ones_are_dashed_with_a_ghost_node_for_unresolved_packages()
    {
        string dot = DotExporter.Export(Sample());
        string[] lines = dot.Split('\n');

        string violated = lines.Single(l => l.Contains("[1.0.0, 1.2.0)", StringComparison.Ordinal));
        Assert.Contains("color=red", violated);

        string ok = lines.Single(l => l.Contains("label=\"2.0.0\"", StringComparison.Ordinal));
        Assert.DoesNotContain("color=", ok);

        string undecided = lines.Single(l => l.Contains("label=\"1.0.0\", style=dashed", StringComparison.Ordinal));
        Assert.Contains("c0:?Lib.Missing", undecided);
        Assert.Single(lines, l => l.Contains("Lib.Missing (not resolved)", StringComparison.Ordinal) && l.Contains("[label=", StringComparison.Ordinal) && !l.Contains("->", StringComparison.Ordinal));
    }

    [Fact]
    public void Each_target_gets_its_own_cluster_and_distinct_node_ids()
    {
        TargetGraph[] targets = [new("net10.0", [Pkg("Lib.A", "1.0.0")]), new("net10.0/linux-x64", [Pkg("Lib.A", "1.0.0")])];

        string dot = DotExporter.Export(Result(targets));

        Assert.Contains("\"cluster_0\"", dot);
        Assert.Contains("\"cluster_1\"", dot);
        Assert.Contains("\"c0:Lib.A@1.0.0\"", dot);
        Assert.Contains("\"c1:Lib.A@1.0.0\"", dot);
    }

    [Fact]
    public void Hostile_package_names_cannot_break_out_of_the_quoted_strings()
    {
        string hostile = "x\"]; system(\"calc\"); //\\";
        HypergraphResult result = Result(new TargetGraph(
            "net10.0",
            [
                Pkg(hostile, "1.0.0", true, ">= 1.0.0", ("Lib.B", "\"quoted\" range \\")),
                Pkg("Lib.B", "1.0.0"),
            ]));

        string dot = DotExporter.Export(result);

        Assert.True(QuotesAreBalanced(dot), "every quoted string must be closed");
        Assert.Contains("x\\\"]; system(\\\"calc\\\"); //\\\\", dot);
        Assert.DoesNotContain("\"x\"]", dot);
    }

    [Fact]
    public void Control_characters_and_line_breaks_in_names_become_spaces()
    {
        HypergraphResult result = Result(new TargetGraph("net10.0", [Pkg("Evil\u001b[31m\nname\u0007", "1.0.0", true, ">= 1.0.0")]));

        string dot = DotExporter.Export(result);

        Assert.False(dot.Contains('\u001b'));
        Assert.False(dot.Contains('\u0007'));
        Assert.Contains("Evil [31m name ", dot);
        Assert.True(QuotesAreBalanced(dot));
    }

    [Fact]
    public void Output_is_stable_and_uses_unix_line_endings()
    {
        HypergraphResult result = Sample();

        Assert.Equal(DotExporter.Export(result), DotExporter.Export(result));
        Assert.DoesNotContain("\r", DotExporter.Export(result));
    }

    [Fact]
    public void An_empty_result_is_a_valid_empty_digraph()
    {
        string dot = DotExporter.Export(new HypergraphResult(1, new ToolInfo("deprisk", "x"), "nuget", []));

        Assert.StartsWith("digraph deprisk {", dot);
        Assert.DoesNotContain("subgraph", dot);
    }

    [Theory]
    [InlineData("plain", "\"plain\"")]
    [InlineData("a\"b", "\"a\\\"b\"")]
    [InlineData("a\\b", "\"a\\\\b\"")]
    [InlineData("a\nb", "\"a b\"")]
    public void Quote_escapes_backslash_and_quote_and_cleans_control_characters(string input, string expected)
    {
        Assert.Equal(expected, DotExporter.Quote(input));
    }
}
