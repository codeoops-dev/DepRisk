using System.Text.Json.Nodes;
using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Core.Reach;
using DepRisk.Data.Reach;
using Xunit;

namespace DepRisk.Data.Tests;

/// <summary>
/// The draft symbol map is built to be refused until a person fills it in (ADR 0024), and every entry the planner calls writable must be
/// accepted by <see cref="SymbolMapLoader"/> once filled in: the planner and the loader keep their own copies of the name rules, and
/// these tests are what keeps them equal.
/// </summary>
public sealed class SymbolTemplateServiceTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "deprisk-symtemplate-" + Guid.NewGuid().ToString("N"));

    public SymbolTemplateServiceTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }

    private static SymbolWorkItem Missing(string advisory, string package) =>
        new(advisory, [], package, ["1.0.0"], true, null, [], SymbolWorkStatus.Missing, false, null);

    private string Write(string json)
    {
        string path = Path.Combine(_dir, Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllText(path, json);
        return path;
    }

    private static Finding Find(string id, string package) =>
        new(id, [], null, null, [], new FindingPackage(package, "1.0.0"), [], [new FindingLocation("App", "t", true)]);

    [Fact]
    public void The_draft_has_the_documented_shape_and_nothing_that_could_be_taken_for_a_claim()
    {
        string json = SymbolTemplateService.DraftJson(SymbolLanguages.JavaScript, [Missing("GHSA-1", "@scope/pkg"), Missing("CVE-2", "lodash")]);

        Assert.EndsWith("\n", json);
        Assert.False(json.Contains('\r'));

        JsonNode root = JsonNode.Parse(json)!;
        Assert.Equal(1, root["schemaVersion"]!.GetValue<int>());
        Assert.Equal("javascript", root["language"]!.GetValue<string>());

        JsonArray entries = root["entries"]!.AsArray();
        Assert.Equal(2, entries.Count);

        foreach (JsonNode? entry in entries)
        {
            Assert.Equal(new[] { "advisory", "package", "symbols", "complete", "source" }, entry!.AsObject().Select(p => p.Key).ToArray());
            Assert.Empty(entry["symbols"]!.AsArray());
            Assert.Null(entry["complete"]);
            Assert.Equal(string.Empty, entry["source"]!.GetValue<string>());
        }
    }

    [Fact]
    public void The_draft_is_deterministic()
    {
        SymbolWorkItem[] items = [Missing("GHSA-1", "A"), Missing("GHSA-2", "B")];

        Assert.Equal(SymbolTemplateService.DraftJson(SymbolLanguages.CSharp, items), SymbolTemplateService.DraftJson(SymbolLanguages.CSharp, items));
    }

    [Fact]
    public void An_empty_draft_is_a_valid_empty_map()
    {
        string path = Write(SymbolTemplateService.DraftJson(SymbolLanguages.CSharp, []));

        Assert.Equal(0, SymbolMapLoader.Load(path).Map.Count);
    }

    [Theory]
    [InlineData("csharp")]
    [InlineData("javascript")]
    public void The_loader_refuses_a_draft_that_is_not_filled_in_and_names_the_entry(string language)
    {
        string path = Write(SymbolTemplateService.DraftJson(language, [Missing("GHSA-1", "lodash")]));

        InvalidInputException error = Assert.Throws<InvalidInputException>(() => SymbolMapLoader.Load(path));

        Assert.Contains("entry 0", error.Message);
    }

    [Fact]
    public void Each_of_the_three_blanks_alone_keeps_the_loader_refusing_the_draft()
    {
        // Decide two of the three and leave the other blank: all three are refused, whichever is left.
        foreach (string blank in new[] { "symbols", "complete", "source" })
        {
            JsonNode root = JsonNode.Parse(SymbolTemplateService.DraftJson(SymbolLanguages.CSharp, [Missing("GHSA-1", "Lib.A")]))!;
            JsonNode entry = root["entries"]![0]!;

            if (blank != "symbols")
            {
                entry["symbols"] = new JsonArray("Lib.A.Thing.Run");
            }

            if (blank != "complete")
            {
                entry["complete"] = false;
            }

            if (blank != "source")
            {
                entry["source"] = "analyst notes";
            }

            string path = Write(root.ToJsonString());
            Assert.Throws<InvalidInputException>(() => SymbolMapLoader.Load(path));
        }
    }

    [Theory]
    [InlineData("csharp", "GHSA-xxxx-1234", "Newtonsoft.Json")]
    [InlineData("csharp", "CVE-2099-0001", "Some.Package-X_y")]
    [InlineData("javascript", "GHSA-1", "lodash")]
    [InlineData("javascript", "GHSA-1", "@scope/pkg")]
    [InlineData("javascript", "GHSA-1", "a.b_c~d")]
    public void A_drafted_entry_is_accepted_by_the_loader_once_it_is_filled_in(string language, string advisory, string package)
    {
        JsonNode root = JsonNode.Parse(SymbolTemplateService.DraftJson(language, [Missing(advisory, package)]))!;
        JsonNode entry = root["entries"]![0]!;
        entry["symbols"] = new JsonArray(language == SymbolLanguages.JavaScript ? "*" : "Some.Ns.Type.Run");
        entry["complete"] = false;
        entry["source"] = "analyst notes";

        SymbolSet set = Assert.Single(SymbolMapLoader.Load(Write(root.ToJsonString())).Map.Sets);

        Assert.Equal(advisory, set.Advisory);
        Assert.Equal(package, set.Package);
        Assert.Equal(language, set.Language);
    }

    [Theory]
    [InlineData("csharp", "GHSA-1", "Newtonsoft.Json")]
    [InlineData("csharp", "GHSA bad", "Lib")]
    [InlineData("csharp", "GHSA-1", "Lib With Space")]
    [InlineData("csharp", "GHSA-1", "@scope/pkg")]
    [InlineData("csharp", "GHSA-1", "Lib/Sub")]
    [InlineData("javascript", "GHSA-1", "lodash")]
    [InlineData("javascript", "GHSA-1", "@scope/pkg")]
    [InlineData("javascript", "GHSA-1", "Lib With Space")]
    [InlineData("javascript", "GHSA-1", "@scope")]
    [InlineData("javascript", "GHSA-1", "a/b/c")]
    [InlineData("javascript", "GHSA:1", "pkg")]
    [InlineData("javascript", "GHSA-1", "pkg\u00e9")]
    public void The_planner_and_the_loader_agree_on_which_names_can_be_an_entry(string language, string advisory, string package)
    {
        SymbolWorkItem item = Assert.Single(SymbolTemplate.Plan([Find(advisory, package)], null, language));

        JsonNode root = JsonNode.Parse(SymbolTemplateService.DraftJson(language, [Missing(advisory, package)]))!;
        JsonNode entry = root["entries"]![0]!;
        entry["symbols"] = new JsonArray(language == SymbolLanguages.JavaScript ? "*" : "Some.Ns.Type.Run");
        entry["complete"] = false;
        entry["source"] = "analyst notes";
        string path = Write(root.ToJsonString());

        bool loaderAccepts;

        try
        {
            SymbolMapLoader.Load(path);
            loaderAccepts = true;
        }
        catch (InvalidInputException)
        {
            loaderAccepts = false;
        }

        Assert.Equal(loaderAccepts, item.Status == SymbolWorkStatus.Missing);
    }
}
