namespace DepRisk.Data.Tests;

/// <summary>
/// OSV records shaped like the NuGet records published by the GitHub Advisory Database
/// (ECOSYSTEM ranges with introduced/fixed events, explicit version lists, severity, database_specific.severity).
/// The ids and package names are invented so no real advisory is misquoted.
/// </summary>
internal static class OsvFixtures
{
    public const string Typical = """
    {
      "schema_version": "1.6.0",
      "id": "GHSA-test-aaaa-0001",
      "modified": "2026-01-01T00:00:00Z",
      "published": "2025-12-01T00:00:00Z",
      "aliases": ["CVE-2025-0001"],
      "summary": "Example.Package allows remote denial of service",
      "details": "A long description that DepRisk does not need.",
      "severity": [
        { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" }
      ],
      "affected": [
        {
          "package": { "ecosystem": "NuGet", "name": "Example.Package" },
          "ranges": [
            { "type": "ECOSYSTEM", "events": [ { "introduced": "0" }, { "fixed": "2.1.5" } ] }
          ],
          "versions": ["1.0.0", "2.0.0", "2.1.0"]
        },
        {
          "package": { "ecosystem": "NuGet", "name": "example.package.extras" },
          "ranges": [
            { "type": "ECOSYSTEM", "events": [ { "introduced": "3.0.0" }, { "fixed": "3.0.2" } ] },
            { "type": "GIT", "repo": "https://example.invalid/repo.git", "events": [ { "introduced": "0" }, { "fixed": "0123456789abcdef0123456789abcdef01234567" } ] }
          ]
        }
      ],
      "references": [ { "type": "ADVISORY", "url": "https://example.invalid/advisory" } ],
      "database_specific": { "cwe_ids": ["CWE-400"], "severity": "HIGH", "github_reviewed": true }
    }
    """;

    public static string Make(string id, string package, string introduced, string? fixedIn, string? severity = "HIGH", string? summary = null)
    {
        string events = fixedIn is null
            ? $"{{ \"introduced\": \"{introduced}\" }}"
            : $"{{ \"introduced\": \"{introduced}\" }}, {{ \"fixed\": \"{fixedIn}\" }}";

        string severityJson = severity is null ? string.Empty : $", \"database_specific\": {{ \"severity\": \"{severity}\" }}";
        string summaryJson = summary is null ? string.Empty : $", \"summary\": {System.Text.Json.JsonSerializer.Serialize(summary)}";

        return $$"""
        {
          "id": "{{id}}",
          "aliases": []{{summaryJson}},
          "affected": [
            {
              "package": { "ecosystem": "NuGet", "name": "{{package}}" },
              "ranges": [ { "type": "ECOSYSTEM", "events": [ {{events}} ] } ]
            }
          ]{{severityJson}}
        }
        """;
    }

    public static string Withdrawn(string id) => $$"""
        { "id": "{{id}}", "withdrawn": "2026-02-01T00:00:00Z",
          "affected": [ { "package": { "ecosystem": "NuGet", "name": "Pkg.Withdrawn" }, "ranges": [ { "type": "ECOSYSTEM", "events": [ { "introduced": "0" } ] } ] } ] }
        """;

    public static string OtherEcosystem(string id) => $$"""
        { "id": "{{id}}",
          "affected": [ { "package": { "ecosystem": "Echo:NuGet", "name": "Pkg.Echo" }, "ranges": [ { "type": "ECOSYSTEM", "events": [ { "introduced": "0" }, { "fixed": "8.0.0+echo.1" } ] } ] } ] }
        """;

    public const string Garbage = "{ this is not json";
}
