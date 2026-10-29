using System.Text;
using DepRisk.Core.Advisories;
using DepRisk.Data.Osv;
using Xunit;

namespace DepRisk.Data.Tests;

public class OsvParserTests
{
    private static OsvParseResult Parse(string json) => OsvParser.Parse(Encoding.UTF8.GetBytes(json));

    [Fact]
    public void A_typical_nuget_record_is_read()
    {
        OsvParseResult result = Parse(OsvFixtures.Typical);

        Assert.Equal(OsvParseStatus.Ok, result.Status);
        Advisory advisory = result.Advisory!;
        Assert.Equal("GHSA-test-aaaa-0001", advisory.Id);
        Assert.Equal(new[] { "CVE-2025-0001" }, advisory.Aliases.ToArray());
        Assert.Equal("Example.Package allows remote denial of service", advisory.Summary);
        Assert.Equal("HIGH", advisory.DatabaseSeverity);
        Assert.False(advisory.Withdrawn);

        AdvisorySeverity score = Assert.Single(advisory.Scores);
        Assert.Equal("CVSS_V3", score.Type);
        Assert.StartsWith("CVSS:3.1/", score.Score);
    }

    [Fact]
    public void Affected_entries_keep_ranges_and_versions_and_git_ranges_are_kept_but_not_evaluated_later()
    {
        Advisory advisory = Parse(OsvFixtures.Typical).Advisory!;

        Assert.Equal(2, advisory.Affected.Count);

        AffectedPackage first = advisory.Affected[0];
        Assert.Equal("Example.Package", first.Name);
        Assert.Equal("NuGet", first.Ecosystem);
        AffectedRange range = Assert.Single(first.Ranges);
        Assert.Equal("ECOSYSTEM", range.Type);
        Assert.Equal(new[] { "introduced:0", "fixed:2.1.5" }, range.Events.Select(e => $"{e.Kind}:{e.Version}").ToArray());
        Assert.Equal(new[] { "1.0.0", "2.0.0", "2.1.0" }, first.Versions.ToArray());

        AffectedPackage second = advisory.Affected[1];
        Assert.Equal(new[] { "ECOSYSTEM", "GIT" }, second.Ranges.Select(r => r.Type).ToArray());
    }

    [Fact]
    public void Unknown_fields_are_ignored()
    {
        OsvParseResult result = Parse("""
            { "id": "X-1", "something_new": { "deep": [1, 2, 3] },
              "affected": [ { "package": { "ecosystem": "NuGet", "name": "P", "purl": "pkg:nuget/P" }, "future": true, "ranges": [] } ] }
            """);

        Assert.Equal(OsvParseStatus.Ok, result.Status);
    }

    [Fact]
    public void A_withdrawn_record_is_reported_as_withdrawn()
    {
        OsvParseResult result = Parse(OsvFixtures.Withdrawn("W-1"));

        Assert.Equal(OsvParseStatus.Withdrawn, result.Status);
        Assert.True(result.Advisory!.Withdrawn);
    }

    [Theory]
    [InlineData("npm")]
    [InlineData("PyPI")]
    [InlineData("Echo:NuGet")]
    public void Records_without_a_nuget_entry_are_not_nuget(string ecosystem)
    {
        OsvParseResult result = Parse($$"""
            { "id": "O-1", "affected": [ { "package": { "ecosystem": "{{ecosystem}}", "name": "x" }, "ranges": [ { "type": "ECOSYSTEM", "events": [ { "introduced": "0" } ] } ] } ] }
            """);

        Assert.Equal(OsvParseStatus.NotNuGet, result.Status);
    }

    [Fact]
    public void A_record_without_any_affected_entries_is_not_nuget()
    {
        Assert.Equal(OsvParseStatus.NotNuGet, Parse("""{ "id": "N-1" }""").Status);
    }

    [Fact]
    public void An_entry_of_another_ecosystem_is_dropped_but_the_nuget_entry_is_kept()
    {
        OsvParseResult result = Parse("""
            { "id": "M-1", "affected": [
              { "package": { "ecosystem": "npm", "name": "a" }, "ranges": [ { "type": "SEMVER", "events": [ { "introduced": "0" } ] } ] },
              { "package": { "ecosystem": "NuGet", "name": "b" }, "ranges": [ { "type": "ECOSYSTEM", "events": [ { "introduced": "0" } ] } ] } ] }
            """);

        Assert.Equal(OsvParseStatus.Ok, result.Status);
        Assert.Equal("b", Assert.Single(result.Advisory!.Affected).Name);
    }

    [Theory]
    [InlineData(OsvFixtures.Garbage)]
    [InlineData("[]")]
    [InlineData("\"text\"")]
    [InlineData("""{ "summary": "no id" }""")]
    [InlineData("""{ "id": "" }""")]
    [InlineData("""{ "id": 7 }""")]
    public void Malformed_records_are_invalid(string json)
    {
        OsvParseResult result = Parse(json);

        Assert.Equal(OsvParseStatus.Invalid, result.Status);
        Assert.NotNull(result.Error);
        Assert.Null(result.Advisory);
    }

    [Fact]
    public void An_unparsable_version_in_an_evaluated_range_makes_the_record_invalid()
    {
        OsvParseResult result = Parse(OsvFixtures.Make("V-1", "Pkg", "0", "not-a-version-!"));

        Assert.Equal(OsvParseStatus.Invalid, result.Status);
        Assert.Contains("not a valid NuGet version", result.Error);
    }

    [Fact]
    public void Git_commit_hashes_in_git_ranges_are_not_validated_as_versions()
    {
        OsvParseResult result = Parse("""
            { "id": "G-1", "affected": [ { "package": { "ecosystem": "NuGet", "name": "P" },
              "ranges": [ { "type": "GIT", "events": [ { "introduced": "0" }, { "fixed": "0123456789abcdef0123456789abcdef01234567" } ] } ] } ] }
            """);

        Assert.Equal(OsvParseStatus.Ok, result.Status);
    }

    [Fact]
    public void Events_with_non_string_values_are_invalid()
    {
        OsvParseResult result = Parse("""
            { "id": "E-1", "affected": [ { "package": { "ecosystem": "NuGet", "name": "P" },
              "ranges": [ { "type": "ECOSYSTEM", "events": [ { "introduced": 0 } ] } ] } ] }
            """);

        Assert.Equal(OsvParseStatus.Invalid, result.Status);
    }

    [Fact]
    public void A_very_long_summary_is_truncated()
    {
        OsvParseResult result = Parse(OsvFixtures.Make("L-1", "Pkg", "0", "1.0.0", summary: new string('x', 5000)));

        string summary = result.Advisory!.Summary!;
        Assert.Equal(OsvParser.MaxSummaryLength + 1, summary.Length);
        Assert.EndsWith("…", summary);
    }

    [Fact]
    public void An_overlong_id_is_invalid()
    {
        Assert.Equal(
            OsvParseStatus.Invalid,
            Parse($$"""{ "id": "{{new string('x', OsvParser.MaxIdLength + 1)}}" }""").Status);
    }

    [Fact]
    public void Deeply_nested_documents_are_rejected_without_crashing()
    {
        string deep = "{\"id\":\"D-1\",\"x\":" + new string('[', 500) + new string(']', 500) + "}";

        Assert.Equal(OsvParseStatus.Invalid, Parse(deep).Status);
    }

    [Fact]
    public void Malformed_severity_entries_are_skipped_not_fatal()
    {
        OsvParseResult result = Parse("""
            { "id": "S-1", "severity": [ 5, { "type": "CVSS_V3" }, { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N" } ],
              "affected": [ { "package": { "ecosystem": "NuGet", "name": "P" }, "ranges": [] } ] }
            """);

        Assert.Equal(OsvParseStatus.Ok, result.Status);
        Assert.Equal("CVSS:3.1/AV:N", Assert.Single(result.Advisory!.Scores).Score);
    }
}
