using DepRisk.Core.Model;
using DepRisk.Core.Reach;
using Xunit;

namespace DepRisk.Core.Tests;

public sealed class SymbolTemplateTests
{
    private static Finding Make(string id, string package, string version, string[]? aliases = null, string? summary = null, string[]? fixedIn = null, bool direct = true) =>
        new(
            id,
            aliases ?? [],
            summary,
            null,
            [],
            new FindingPackage(package, version),
            fixedIn ?? [],
            [new FindingLocation("App", "net10.0", direct)]);

    private static SymbolMap MapOf(string language, string advisory, string package, bool complete) =>
        new([new SymbolSet(advisory, package, language == SymbolLanguages.JavaScript ? ["*"] : ["A.B.C"], complete, ["test"], language)]);

    [Fact]
    public void One_item_per_advisory_and_package_whatever_the_versions()
    {
        Finding[] findings =
        [
            Make("GHSA-1", "Lib.A", "1.0.0", ["CVE-1"], "first summary", ["1.2.0"], direct: false),
            Make("GHSA-1", "Lib.A", "1.1.0", ["CVE-1", "CVE-2"], "second summary", ["1.2.0", "2.0.0"], direct: true),
        ];

        SymbolWorkItem item = Assert.Single(SymbolTemplate.Plan(findings, null, SymbolLanguages.CSharp));

        Assert.Equal("GHSA-1", item.Advisory);
        Assert.Equal("Lib.A", item.Package);
        Assert.Equal(new[] { "1.0.0", "1.1.0" }, item.InstalledVersions);
        Assert.Equal(new[] { "CVE-1", "CVE-2" }, item.Aliases);
        Assert.Equal(new[] { "1.2.0", "2.0.0" }, item.FixedVersions);
        Assert.Equal("first summary", item.Summary);
        Assert.True(item.Direct);
        Assert.Equal(SymbolWorkStatus.Missing, item.Status);
    }

    [Fact]
    public void The_same_advisory_in_two_packages_is_two_items_in_a_fixed_order()
    {
        Finding[] findings =
        [
            Make("GHSA-2", "Zed", "1.0.0"),
            Make("GHSA-1", "Beta", "1.0.0"),
            Make("GHSA-1", "Alpha", "1.0.0"),
        ];

        IReadOnlyList<SymbolWorkItem> items = SymbolTemplate.Plan(findings, null, SymbolLanguages.CSharp);

        Assert.Equal(new[] { "GHSA-1|Alpha", "GHSA-1|Beta", "GHSA-2|Zed" }, items.Select(i => i.Advisory + "|" + i.Package).ToArray());
    }

    [Fact]
    public void An_alias_that_repeats_the_id_is_not_listed()
    {
        SymbolWorkItem item = Assert.Single(SymbolTemplate.Plan([Make("GHSA-1", "Lib.A", "1.0.0", ["ghsa-1", "CVE-9"])], null, SymbolLanguages.CSharp));

        Assert.Equal(new[] { "CVE-9" }, item.Aliases);
    }

    [Fact]
    public void An_existing_entry_covers_the_pair_by_id_or_by_alias_and_keeps_its_completeness()
    {
        Finding finding = Make("GHSA-1", "Lib.A", "1.0.0", ["CVE-7"]);

        SymbolWorkItem byId = Assert.Single(SymbolTemplate.Plan([finding], MapOf(SymbolLanguages.CSharp, "ghsa-1", "lib.a", complete: true), SymbolLanguages.CSharp));
        Assert.Equal(SymbolWorkStatus.Covered, byId.Status);
        Assert.True(byId.ExistingComplete);

        SymbolWorkItem byAlias = Assert.Single(SymbolTemplate.Plan([finding], MapOf(SymbolLanguages.CSharp, "CVE-7", "Lib.A", complete: false), SymbolLanguages.CSharp));
        Assert.Equal(SymbolWorkStatus.Covered, byAlias.Status);
        Assert.False(byAlias.ExistingComplete);
    }

    [Fact]
    public void An_entry_for_another_package_or_another_language_does_not_cover_the_pair()
    {
        Finding finding = Make("GHSA-1", "lib-a", "1.0.0");

        Assert.Equal(SymbolWorkStatus.Missing, Assert.Single(SymbolTemplate.Plan([finding], MapOf(SymbolLanguages.JavaScript, "GHSA-1", "other-lib", true), SymbolLanguages.JavaScript)).Status);
        Assert.Equal(SymbolWorkStatus.Missing, Assert.Single(SymbolTemplate.Plan([finding], MapOf(SymbolLanguages.CSharp, "GHSA-1", "lib-a", true), SymbolLanguages.JavaScript)).Status);
    }

    [Theory]
    [InlineData("GHSA-xxxx-1234", "Newtonsoft.Json", "csharp", true)]
    [InlineData("CVE-2099-0001", "Some.Package-X_y", "csharp", true)]
    [InlineData("GHSA bad", "Lib", "csharp", false)]
    [InlineData("GHSA-1", "Lib With Space", "csharp", false)]
    [InlineData("GHSA-1", "@scope/pkg", "csharp", false)]
    [InlineData("GHSA-1", "@scope/pkg", "javascript", true)]
    [InlineData("GHSA-1", "lodash", "javascript", true)]
    [InlineData("GHSA-1", "Lib With Space", "javascript", false)]
    [InlineData("", "lodash", "javascript", false)]
    public void Pairs_that_cannot_be_an_entry_are_reported_not_drafted(string advisory, string package, string language, bool writable)
    {
        SymbolWorkItem item = Assert.Single(SymbolTemplate.Plan([Make(advisory, package, "1.0.0")], null, language));

        Assert.Equal(writable ? SymbolWorkStatus.Missing : SymbolWorkStatus.Unwritable, item.Status);
        Assert.Equal(writable, item.Problem is null);
    }

    [Fact]
    public void An_unknown_language_is_refused()
    {
        Assert.Throws<ArgumentException>(() => SymbolTemplate.Plan([], null, "cobol"));
    }

    [Fact]
    public void No_findings_means_no_work()
    {
        Assert.Empty(SymbolTemplate.Plan([], null, SymbolLanguages.CSharp));
    }
}
