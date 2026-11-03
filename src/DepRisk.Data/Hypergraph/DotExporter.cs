using System.Text;
using DepRisk.Core;
using DepRisk.Core.Hypergraph;

namespace DepRisk.Data.Hypergraph;

/// <summary>
/// Graphviz DOT export of a hypergraph as a bipartite graph: packages are boxes, each hyperedge is a small point node that
/// its owner points to and that points to every package it requires (labelled with the declared range; violated requirements
/// in red, undecided ones dashed). One cluster per project and target. All text comes from package data and is untrusted:
/// every identifier and label is cleaned of control characters and written as a properly escaped quoted string, so
/// package names cannot break out of the DOT syntax.
/// </summary>
public static class DotExporter
{
    private const int Limit = 400;

    public static string Export(HypergraphResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        StringBuilder dot = new();
        dot.Append("digraph deprisk {\n");
        dot.Append("  rankdir=LR;\n");
        dot.Append("  node [shape=box, fontname=\"Helvetica\"];\n");
        dot.Append("  edge [fontname=\"Helvetica\", fontsize=10];\n");

        int cluster = 0;

        foreach (ProjectHypergraph project in result.Projects)
        {
            foreach (TargetHypergraph target in project.Targets)
            {
                string prefix = $"c{cluster}:";
                dot.Append($"  subgraph {Quote("cluster_" + cluster)} {{\n");
                dot.Append($"    label={Quote($"{project.Name} ({target.Name})")};\n");

                foreach (HypergraphNode node in target.Nodes)
                {
                    string style = node.IsDirect ? ", style=filled, fillcolor=\"#e8f0fe\"" : string.Empty;
                    dot.Append($"    {Quote(prefix + (node.Path ?? node.Id + "@" + node.Version))} [label={Quote(node.Id + " " + node.Version)}{style}];\n");
                }

                HashSet<string> ghosts = new(StringComparer.Ordinal);

                foreach (Hyperedge edge in target.Hyperedges)
                {
                    string ownerId = edge.Kind == "project" ? prefix + "project:" + edge.Owner : prefix + (edge.Path ?? edge.Owner);
                    string pointId = prefix + "h:" + edge.Id;

                    if (edge.Kind == "project")
                    {
                        dot.Append($"    {Quote(ownerId)} [label={Quote(edge.Owner)}, shape=house, style=filled, fillcolor=\"#fff4ce\"];\n");
                    }

                    dot.Append($"    {Quote(pointId)} [shape=point, width=0.12];\n");
                    dot.Append($"    {Quote(ownerId)} -> {Quote(pointId)} [arrowhead=none];\n");

                    foreach (Requirement requirement in edge.Requires)
                    {
                        string targetId = prefix + (requirement.ResolvedPath ?? requirement.Package + "@" + requirement.Resolved);

                        if (requirement.Resolved is null)
                        {
                            targetId = prefix + "?" + requirement.Package;

                            if (ghosts.Add(targetId))
                            {
                                dot.Append($"    {Quote(targetId)} [label={Quote(requirement.Package + " (not resolved)")}, style=dashed];\n");
                            }
                        }

                        string attributes = requirement.Satisfied switch
                        {
                            false => ", color=red, fontcolor=red, penwidth=2",
                            null => ", style=dashed, color=gray50",
                            _ => string.Empty,
                        };

                        dot.Append($"    {Quote(pointId)} -> {Quote(targetId)} [label={Quote(requirement.Range ?? string.Empty)}{attributes}];\n");
                    }
                }

                dot.Append("  }\n");
                cluster++;
            }
        }

        dot.Append("}\n");
        return dot.ToString();
    }

    /// <summary>A DOT double-quoted string: control characters become spaces, backslash and quote are escaped.</summary>
    public static string Quote(string text)
    {
        string cleaned = SafeText.Clean(text, Limit).Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal);
        return "\"" + cleaned + "\"";
    }
}
