using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Core.Vex;

namespace DepRisk.Data.OpenVex;

/// <summary>What the author of the document asserts: who, about which product, when, and with which tool.</summary>
public sealed record OpenVexOptions(string Product, string Author, string? Role, DateTimeOffset Timestamp, string Tooling);

/// <summary>
/// Writes an OpenVEX 0.2.0 document (https://github.com/openvex/spec): one statement per finding (advisory, package, version) for the
/// product named by the author, with the vulnerable package as a subcomponent. The statuses come from <see cref="VexDecision"/>.
/// The document id is derived from the content, so the same inputs (and timestamp) give the same document.
/// </summary>
public static class OpenVexWriter
{
    public const string Context = "https://openvex.dev/ns/v0.2.0";

    private static readonly JsonSerializerOptions Indented = new()
    {
        WriteIndented = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static string Serialize(RankingResult ranking, ReachabilityResult? reach, OpenVexOptions options)
    {
        ArgumentNullException.ThrowIfNull(ranking);
        ArgumentNullException.ThrowIfNull(options);

        string timestamp = options.Timestamp.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

        JsonArray statements = [];

        foreach (RankedFinding finding in ranking.Findings
                     .OrderBy(f => f.Id, StringComparer.Ordinal)
                     .ThenBy(f => f.Package.Id, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(f => f.Package.Version, StringComparer.Ordinal))
        {
            statements.Add(Statement(finding, VexDecision.For(finding, reach), ranking.Ecosystem, options.Product));
        }

        // The id is a digest of what the document says, so a changed statement is a new document.
        string content = statements.ToJsonString() + "\n" + options.Author + "\n" + options.Product + "\n" + timestamp;

        JsonObject document = new()
        {
            ["@context"] = Context,
            ["@id"] = "urn:deprisk:vex:sha256:" + Digest.Sha256Hex(content),
            ["author"] = options.Author,
        };

        if (!string.IsNullOrWhiteSpace(options.Role))
        {
            document["role"] = options.Role;
        }

        document["timestamp"] = timestamp;
        document["version"] = 1;
        document["tooling"] = options.Tooling;
        document["statements"] = statements;

        return document.ToJsonString(Indented) + "\n";
    }

    private static JsonObject Statement(RankedFinding finding, VexStatement decision, string ecosystem, string product)
    {
        JsonArray aliases = [];

        foreach (string alias in finding.Aliases.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal))
        {
            aliases.Add(alias);
        }

        JsonObject vulnerability = new()
        {
            ["@id"] = "https://osv.dev/vulnerability/" + Uri.EscapeDataString(finding.Id),
            ["name"] = finding.Id,
        };

        if (finding.Summary is { Length: > 0 } summary)
        {
            vulnerability["description"] = summary;
        }

        if (aliases.Count > 0)
        {
            vulnerability["aliases"] = aliases;
        }

        JsonObject statement = new()
        {
            ["vulnerability"] = vulnerability,
            ["products"] = new JsonArray(new JsonObject
            {
                ["@id"] = product,
                ["subcomponents"] = new JsonArray(new JsonObject { ["@id"] = PackageUrl(ecosystem, finding.Package.Id, finding.Package.Version) }),
            }),
            ["status"] = decision.Status,
        };

        if (decision.Justification is not null)
        {
            statement["justification"] = decision.Justification;
        }

        if (decision.ImpactStatement is not null)
        {
            statement["impact_statement"] = decision.ImpactStatement;
        }

        if (decision.ActionStatement is not null)
        {
            statement["action_statement"] = decision.ActionStatement;
        }

        if (decision.StatusNotes is not null)
        {
            statement["status_notes"] = decision.StatusNotes;
        }

        return statement;
    }

    /// <summary>A Package URL (https://github.com/package-url/purl-spec): <c>pkg:nuget/Id@Version</c>, <c>pkg:npm/%40scope/name@Version</c>.</summary>
    public static string PackageUrl(string ecosystem, string id, string version)
    {
        string type = ecosystem == Ecosystem.Npm.Id ? "npm" : "nuget";
        string name = string.Join('/', id.Split('/').Select(Uri.EscapeDataString));

        return new StringBuilder("pkg:").Append(type).Append('/').Append(name).Append('@').Append(Uri.EscapeDataString(version)).ToString();
    }
}
