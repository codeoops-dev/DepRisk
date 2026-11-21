using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Core.Reach;

namespace DepRisk.Data.Reach;

public sealed record SymbolTemplateOptions(string ScanPath, string AdvisoriesPath, string? SymbolsPath, Ecosystem? Ecosystem, bool Strict);

/// <param name="DraftJson">A symbol map (symbol-map.v1 shape) with one entry for each <see cref="SymbolWorkStatus.Missing"/> item. It is refused by the loader until a person fills it in.</param>
public sealed record SymbolTemplateOutcome(
    string Ecosystem,
    string Language,
    AdvisorySourceInfo Advisories,
    SymbolMapInfo? SymbolMaps,
    IReadOnlyList<SymbolWorkItem> Items,
    string DraftJson,
    string InputsDigest);

/// <summary>
/// <c>deprisk symbols template</c> (ADR 0024): finds the advisory and package pairs of a project that <c>reach</c> would ask about, leaves out
/// the ones an existing symbol map covers, and drafts an entry for the rest. The draft is built to fail: <c>symbols</c> is empty,
/// <c>complete</c> is null and <c>source</c> is empty, so <see cref="SymbolMapLoader"/> refuses it (naming the entry) until someone has made
/// all three decisions. It can never be read as "no symbols known", and it never contains a symbol nobody chose.
/// </summary>
public static class SymbolTemplateService
{
    public static SymbolTemplateOutcome Run(SymbolTemplateOptions options, ToolInfo tool)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(tool);

        FindingsOutcome matched = FindingsService.Match(options.ScanPath, options.AdvisoriesPath, tool, options.Strict, options.Ecosystem);
        FindingsResult findings = matched.Result;

        string language = ReachService.LanguageOf(findings.Ecosystem)
            ?? throw new InvalidInputException($"there is no analyzer for the ecosystem '{SafeText.Clean(findings.Ecosystem, 40)}', so there are no symbol maps for it.");

        LoadedSymbolMaps? maps = options.SymbolsPath is null ? null : SymbolMapLoader.Load(options.SymbolsPath);
        IReadOnlyList<SymbolWorkItem> items = SymbolTemplate.Plan(findings.Findings, maps?.Map, language);
        string draft = DraftJson(language, items.Where(i => i.Status == SymbolWorkStatus.Missing));

        string inputs = Digest.Sha256Hex($"findings:{matched.InputsDigest}\nsymbols:{maps?.Info.Digest ?? "none"}\n");

        return new SymbolTemplateOutcome(findings.Ecosystem, language, findings.Advisories, maps?.Info, items, draft, inputs);
    }

    /// <summary>The draft file: deterministic, LF line endings, a final newline.</summary>
    public static string DraftJson(string language, IEnumerable<SymbolWorkItem> missing)
    {
        using MemoryStream stream = new();

        using (Utf8JsonWriter writer = new(stream, new JsonWriterOptions { Indented = true, NewLine = "\n", Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", 1);
            writer.WriteString("language", language);
            writer.WriteStartArray("entries");

            foreach (SymbolWorkItem item in missing)
            {
                writer.WriteStartObject();
                writer.WriteString("advisory", item.Advisory);
                writer.WriteString("package", item.Package);
                writer.WriteStartArray("symbols");
                writer.WriteEndArray();
                writer.WriteNull("complete");
                writer.WriteString("source", string.Empty);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray()) + "\n";
    }
}
