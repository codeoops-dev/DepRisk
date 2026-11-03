using System.Text;
using DepRisk.Core;
using DepRisk.Core.Advisories;
using DepRisk.Data.Osv;
using Xunit;

namespace DepRisk.Data.Tests;

public sealed class NpmOsvTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-osv-npm-" + Guid.NewGuid().ToString("N"));

    public NpmOsvTests() => Directory.CreateDirectory(_root);

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private static OsvParseResult Parse(string json, Ecosystem ecosystem) => OsvParser.Parse(Encoding.UTF8.GetBytes(json), ecosystem);

    private const string NpmRecord = """
    {
      "id": "GHSA-test-npm-0001",
      "aliases": ["CVE-2099-1111"],
      "summary": "Synthetic npm advisory",
      "database_specific": { "severity": "HIGH" },
      "affected": [
        {
          "package": { "ecosystem": "npm", "name": "ms" },
          "ranges": [ { "type": "SEMVER", "events": [ { "introduced": "0" }, { "fixed": "2.1.3" } ] } ]
        }
      ]
    }
    """;

    private const string BothRecord = """
    {
      "id": "BOTH-1",
      "affected": [
        { "package": { "ecosystem": "NuGet", "name": "Some.Package" }, "ranges": [ { "type": "ECOSYSTEM", "events": [ { "introduced": "0" }, { "fixed": "2.0.0" } ] } ] },
        { "package": { "ecosystem": "npm", "name": "some-package" }, "ranges": [ { "type": "SEMVER", "events": [ { "introduced": "0" }, { "fixed": "3.0.0" } ] } ] }
      ]
    }
    """;

    [Fact]
    public void An_npm_record_is_read_for_npm_and_is_another_ecosystem_for_nuget()
    {
        OsvParseResult npm = Parse(NpmRecord, Ecosystem.Npm);

        Assert.Equal(OsvParseStatus.Ok, npm.Status);
        AffectedPackage affected = Assert.Single(npm.Advisory!.Affected);
        Assert.Equal("npm", affected.Ecosystem);
        Assert.Equal("ms", affected.Name);

        Assert.Equal(OsvParseStatus.OtherEcosystem, Parse(NpmRecord, Ecosystem.NuGet).Status);
        Assert.Equal(OsvParseStatus.OtherEcosystem, OsvParser.Parse(Encoding.UTF8.GetBytes(NpmRecord)).Status);   // the default is NuGet
    }

    [Fact]
    public void A_record_for_several_ecosystems_keeps_only_the_requested_entries()
    {
        OsvParseResult npm = Parse(BothRecord, Ecosystem.Npm);
        OsvParseResult nuget = Parse(BothRecord, Ecosystem.NuGet);

        Assert.Equal("some-package", Assert.Single(npm.Advisory!.Affected).Name);
        Assert.Equal("Some.Package", Assert.Single(nuget.Advisory!.Affected).Name);
    }

    [Theory]
    [InlineData("Echo:npm")]
    [InlineData("npm:vendor")]
    [InlineData("PyPI")]
    public void Vendor_and_other_ecosystems_are_not_npm(string ecosystem)
    {
        string json = NpmRecord.Replace("\"ecosystem\": \"npm\"", $"\"ecosystem\": \"{ecosystem}\"", StringComparison.Ordinal);

        Assert.Equal(OsvParseStatus.OtherEcosystem, Parse(json, Ecosystem.Npm).Status);
    }

    [Fact]
    public void The_ecosystem_name_is_matched_ignoring_case_like_for_nuget()
    {
        string json = NpmRecord.Replace("\"ecosystem\": \"npm\"", "\"ecosystem\": \"NPM\"", StringComparison.Ordinal);

        Assert.Equal(OsvParseStatus.Ok, Parse(json, Ecosystem.Npm).Status);
    }

    [Theory]
    [InlineData("1.2.3.4")]
    [InlineData("1.2")]
    [InlineData("v1.2.3")]
    [InlineData("^1.2.3")]
    public void A_range_version_that_is_not_semver_makes_the_record_invalid_for_npm(string version)
    {
        string json = NpmRecord.Replace("\"fixed\": \"2.1.3\"", $"\"fixed\": \"{version}\"", StringComparison.Ordinal);

        OsvParseResult result = Parse(json, Ecosystem.Npm);

        Assert.Equal(OsvParseStatus.Invalid, result.Status);
        Assert.Contains("not a valid npm version", result.Error);
    }

    [Fact]
    public void The_same_four_part_version_is_fine_for_nuget()
    {
        string json = BothRecord.Replace("\"fixed\": \"2.0.0\"", "\"fixed\": \"2.0.0.1\"", StringComparison.Ordinal);

        Assert.Equal(OsvParseStatus.Ok, Parse(json, Ecosystem.NuGet).Status);
    }

    [Fact]
    public void The_loader_keeps_npm_advisories_and_counts_everything_else()
    {
        File.WriteAllText(Path.Combine(_root, "npm.json"), NpmRecord);
        File.WriteAllText(Path.Combine(_root, "both.json"), BothRecord);
        File.WriteAllText(Path.Combine(_root, "nuget-only.json"), """
            { "id": "N-1", "affected": [ { "package": { "ecosystem": "NuGet", "name": "X" }, "ranges": [ { "type": "ECOSYSTEM", "events": [ { "introduced": "0" } ] } ] } ] }
            """);
        File.WriteAllText(Path.Combine(_root, "withdrawn.json"), """{ "id": "W-1", "withdrawn": "2024-01-01T00:00:00Z" }""");
        File.WriteAllText(Path.Combine(_root, "bad.json"), "{ nope");

        AdvisorySnapshot npm = AdvisorySnapshotLoader.Load(_root, Ecosystem.Npm);

        Assert.Equal(new[] { "BOTH-1", "GHSA-test-npm-0001" }, npm.Advisories.Select(a => a.Id).ToArray());
        Assert.Equal(1, npm.SkippedOtherEcosystem);
        Assert.Equal(1, npm.SkippedWithdrawn);
        Assert.Equal(1, npm.SkippedInvalid);

        AdvisorySnapshot nuget = AdvisorySnapshotLoader.Load(_root, Ecosystem.NuGet);

        Assert.Equal(new[] { "BOTH-1", "N-1" }, nuget.Advisories.Select(a => a.Id).ToArray());
        Assert.Equal(1, nuget.SkippedOtherEcosystem);

        // The digest identifies the data, not the ecosystem it was read for.
        Assert.Equal(nuget.Digest, npm.Digest);
        Assert.Equal(nuget.Digest, AdvisorySnapshotLoader.Load(_root).Digest);
    }
}
