using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using DepRisk.Core;
using DepRisk.Core.Cvss;
using DepRisk.Core.Model;
using DepRisk.Core.Ranking;

namespace DepRisk.Data.Sarif;

/// <summary>
/// Writes a <see cref="RankingResult"/> as SARIF 2.1.0 (https://docs.oasis-open.org/sarif/sarif/v2.1.0/), for code-scanning
/// platforms such as GitHub. One rule per advisory, one result per finding (ordered by rank), located at the project files
/// that use the affected package. Deterministic: no timestamps, no absolute paths. Text from advisory data is cleaned of
/// control characters and bounded.
/// </summary>
public static class SarifWriter
{
    public const string SchemaUri = "https://json.schemastore.org/sarif-2.1.0.json";

    private const int MessageLimit = 600;
    private const int ShortLimit = 200;

    public static string Serialize(RankingResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        List<string> ruleIds = result.Findings
            .Select(f => f.Id)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToList();

        Dictionary<string, int> ruleIndex = ruleIds
            .Select((id, index) => (id, index))
            .ToDictionary(x => x.id, x => x.index, StringComparer.Ordinal);

        JsonArray rules = [];

        foreach (string id in ruleIds)
        {
            rules.Add(BuildRule(result.Findings.First(f => f.Id == id)));
        }

        JsonArray results = [];

        foreach (RankedFinding finding in result.Findings)
        {
            results.Add(BuildResult(finding, ruleIndex[finding.Id]));
        }

        JsonObject run = new()
        {
            ["tool"] = new JsonObject
            {
                ["driver"] = new JsonObject
                {
                    ["name"] = "DepRisk",
                    ["semanticVersion"] = result.Tool.Version,
                    ["informationUri"] = ProductInfo.RepositoryUrl,
                    ["rules"] = rules,
                },
            },
            ["results"] = results,
            ["properties"] = new JsonObject
            {
                ["deprisk"] = new JsonObject
                {
                    ["method"] = result.Method,
                    ["ordering"] = new JsonArray(result.Ordering.Select(o => (JsonNode?)o).ToArray()),
                    ["advisoriesDigest"] = result.Advisories.Digest,
                    ["epssDigest"] = result.Signals.Epss?.Digest,
                    ["kevDigest"] = result.Signals.Kev?.Digest,
                    ["note"] = "Matching is by package version only; reachability is not considered.",
                },
            },
        };

        JsonObject root = new()
        {
            ["$schema"] = SchemaUri,
            ["version"] = "2.1.0",
            ["runs"] = new JsonArray(run),
        };

        return JsonSerializer.Serialize(root, OutputJson.Options) + "\n";
    }

    /// <summary>The SARIF level of a finding: error, warning, or note (see ADR 0008).</summary>
    public static string LevelFor(RankedFinding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        if (finding.Signals.Kev is not null)
        {
            return "error";
        }

        string? rating = finding.Signals.Cvss?.Rating ?? finding.Severity;

        return rating?.ToUpperInvariant() switch
        {
            "CRITICAL" or "HIGH" => "error",
            "MEDIUM" or "MODERATE" => "warning",
            "LOW" or "NONE" => "note",
            _ => "warning",
        };
    }

    private static JsonObject BuildRule(RankedFinding finding)
    {
        string summary = SafeText.Clean(finding.Summary, MessageLimit);
        string shortText = summary.Length > 0 ? SafeText.Clean(finding.Summary, ShortLimit) : SafeText.Clean(finding.Id, ShortLimit);

        string help = finding.FixedVersions.Count > 0
            ? $"Upgrade {SafeText.Clean(finding.Package.Id, 100)} to {SafeText.Clean(finding.FixedVersions[0], 60)} or later."
            : "No fixed version is known yet.";

        JsonArray tags = ["security", "dependency", "vulnerability"];

        if (finding.Signals.Kev is not null)
        {
            tags.Add("known-exploited");
        }

        JsonObject properties = new() { ["tags"] = tags };

        if (finding.Signals.Cvss is { } cvss)
        {
            // GitHub code scanning shows this 0-10 value as the alert's severity.
            properties["security-severity"] = CvssV3.Format(cvss.BaseScore);
        }

        if (finding.Aliases.Count > 0)
        {
            properties["aliases"] = new JsonArray(finding.Aliases.Select(a => (JsonNode?)SafeText.Clean(a, 100)).ToArray());
        }

        return new JsonObject
        {
            ["id"] = finding.Id,
            ["shortDescription"] = new JsonObject { ["text"] = shortText },
            ["help"] = new JsonObject { ["text"] = help },
            ["helpUri"] = "https://osv.dev/vulnerability/" + Uri.EscapeDataString(finding.Id),
            ["defaultConfiguration"] = new JsonObject { ["level"] = LevelFor(finding) },
            ["properties"] = properties,
        };
    }

    private static JsonObject BuildResult(RankedFinding finding, int ruleIndex)
    {
        JsonArray locations = [];

        foreach (string uri in finding.Locations.Select(l => EscapePath(l.ProjectFile ?? l.Project)).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal))
        {
            locations.Add(new JsonObject
            {
                ["physicalLocation"] = new JsonObject
                {
                    ["artifactLocation"] = new JsonObject { ["uri"] = uri, ["uriBaseId"] = "%SRCROOT%" },
                    ["region"] = new JsonObject { ["startLine"] = 1 },
                },
            });
        }

        JsonObject properties = new()
        {
            ["rank"] = finding.Rank,
            ["package"] = new JsonObject { ["id"] = finding.Package.Id, ["version"] = finding.Package.Version },
            ["direct"] = finding.Locations.Any(l => l.IsDirect),
            ["kev"] = finding.Signals.Kev is not null,
            ["fixedVersions"] = new JsonArray(finding.FixedVersions.Select(v => (JsonNode?)v).ToArray()),
            ["projects"] = new JsonArray(finding.Locations.Select(l => l.Project).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).Select(p => (JsonNode?)p).ToArray()),
        };

        if (finding.Signals.Epss is { } epss)
        {
            properties["epss"] = epss.Probability;
        }

        if (finding.Signals.Cvss is { } cvss)
        {
            properties["cvss"] = cvss.BaseScore;
        }

        return new JsonObject
        {
            ["ruleId"] = finding.Id,
            ["ruleIndex"] = ruleIndex,
            ["level"] = LevelFor(finding),
            ["message"] = new JsonObject { ["text"] = Message(finding) },
            ["locations"] = locations,
            ["partialFingerprints"] = new JsonObject
            {
                ["deprisk/v1"] = Digest.Sha256Hex($"{finding.Id}\n{finding.Package.Id.ToLowerInvariant()}\n{finding.Package.Version}"),
            },
            ["properties"] = properties,
        };
    }

    private static string Message(RankedFinding finding)
    {
        List<string> parts =
        [
            $"{finding.Package.Id} {finding.Package.Version} is affected by {finding.Id}.",
        ];

        if (!string.IsNullOrWhiteSpace(finding.Summary))
        {
            parts.Add(finding.Summary.Trim().TrimEnd('.') + ".");
        }

        parts.Add(finding.FixedVersions.Count > 0 ? $"Fixed in {string.Join(", ", finding.FixedVersions)}." : "No fixed version is known.");

        if (finding.Signals.Kev is { } kev)
        {
            parts.Add(kev.KnownRansomwareUse ? "Listed in the CISA KEV catalog (known ransomware use)." : "Listed in the CISA KEV catalog.");
        }

        if (finding.Signals.Epss is { } epss)
        {
            parts.Add($"EPSS {epss.Probability.ToString("0.000", CultureInfo.InvariantCulture)}.");
        }

        if (finding.Signals.Cvss is { } cvss)
        {
            parts.Add($"CVSS {CvssV3.Format(cvss.BaseScore)} {cvss.Rating}.");
        }

        parts.Add($"Priority rank {finding.Rank}.");
        return SafeText.Clean(string.Join(' ', parts), MessageLimit);
    }

    /// <summary>Percent-escapes each path segment; '/' separators are kept. Backslashes are treated as separators.</summary>
    public static string EscapePath(string path) =>
        string.Join('/', path.Replace('\\', '/').Split('/').Select(Uri.EscapeDataString));
}
