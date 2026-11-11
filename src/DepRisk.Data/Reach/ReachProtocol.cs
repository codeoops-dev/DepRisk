using System.Text.Json;
using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Core.Reach;

namespace DepRisk.Data.Reach;

/// <summary>One thing to ask the analyzer: the symbols of one advisory in one package.</summary>
public sealed record ReachTarget(string Key, IReadOnlyList<string> Symbols, bool Complete);

public sealed record AnalyzerVerdict(string Label, string Reason, string? Symbol, IReadOnlyList<ReachPathEdge> Path);

public sealed record AnalyzerOutput(
    string AnalyzerName,
    string AnalyzerVersion,
    string SourceDigest,
    ReachSourceInfo Source,
    IReadOnlyDictionary<string, AnalyzerVerdict> Verdicts,
    IReadOnlyList<string> Diagnostics);

/// <summary>
/// The JSON protocol with the analyzer (schemas/reach-request.v1.schema.json, reach-result.v1.schema.json). The request is
/// built here; the result is parsed strictly, because it comes from another process: anything that does not follow the protocol is
/// an <see cref="AnalyzerException"/>, never a guess.
/// </summary>
public static class ReachProtocol
{
    public const int SchemaVersion = 1;
    public const string AnalyzerName = "deprisk-reach";
    private const int MaxPathEdges = 100;

    private static readonly JsonDocumentOptions DocumentOptions = new() { MaxDepth = 32, CommentHandling = JsonCommentHandling.Disallow };

    public static string BuildRequest(
        string root,
        string entrypointMode,
        IReadOnlyList<string> explicitEntrypoints,
        IReadOnlyList<ReachTarget> targets,
        string language = SymbolLanguages.CSharp)
    {
        var request = new
        {
            schemaVersion = SchemaVersion,
            language,
            root,
            entrypoints = new { mode = entrypointMode, @explicit = explicitEntrypoints },
            targets = targets.Select(t => new { key = t.Key, symbols = t.Symbols, complete = t.Complete }).ToList(),
        };

        return JsonSerializer.Serialize(request, new JsonSerializerOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
    }

    public static AnalyzerOutput ParseResult(string json, IReadOnlyCollection<string> expectedKeys, string expectedLanguage = SymbolLanguages.CSharp)
    {
        JsonDocument document;

        try
        {
            document = JsonDocument.Parse(json, DocumentOptions);
        }
        catch (JsonException ex)
        {
            throw new AnalyzerException($"the analyzer's result is not valid JSON ({ex.Message})", ex);
        }

        using (document)
        {
            JsonElement root = document.RootElement;

            if (Int(root, "schemaVersion") != SchemaVersion)
            {
                throw Invalid("unsupported schemaVersion");
            }

            JsonElement analyzer = Object(root, "analyzer");
            string name = Str(analyzer, "name", 64);

            if (name != AnalyzerName || Str(root, "language", 16) != expectedLanguage)
            {
                throw Invalid($"not the {(expectedLanguage == SymbolLanguages.CSharp ? "C#" : "JavaScript and TypeScript")} reachability analyzer");
            }

            string version = Str(analyzer, "version", 64);
            string sourceDigest = Str(root, "sourceDigest", 64);

            if (!Digest.IsSha256Hex(sourceDigest))
            {
                throw Invalid("'sourceDigest' is not a SHA-256");
            }

            JsonElement stats = Object(root, "stats");
            ReachSourceInfo source = new(
                sourceDigest,
                Int(stats, "files"),
                Int(stats, "filesSkipped"),
                Int(stats, "filesWithErrors"),
                Int(stats, "methods"),
                Int(stats, "edges"),
                Int(stats, "entrypoints"));

            Dictionary<string, AnalyzerVerdict> verdicts = new(StringComparer.Ordinal);

            foreach (JsonElement result in Array(root, "results").EnumerateArray())
            {
                string key = Str(result, "key", 1000);
                string label = Str(result, "label", 32);
                string reason = Str(result, "reason", 64);

                if (!ReachLabels.AllLabels.Contains(label) || !ReachLabels.AnalyzerReasons.Contains(reason))
                {
                    throw Invalid($"unknown label or reason ('{SafeText.Clean(label, 40)}', '{SafeText.Clean(reason, 40)}')");
                }

                if (!verdicts.TryAdd(key, new AnalyzerVerdict(label, reason, OptionalStr(result, "symbol", 600), ReadPath(result))))
                {
                    throw Invalid("a key appears twice");
                }
            }

            if (verdicts.Count != expectedKeys.Count || !expectedKeys.All(verdicts.ContainsKey))
            {
                throw Invalid("the results do not match the targets that were asked about");
            }

            List<string> diagnostics = [];

            foreach (JsonElement d in Array(root, "diagnostics").EnumerateArray().Take(20))
            {
                string file = OptionalStr(d, "file", 300) ?? string.Empty;
                string message = Str(d, "message", 300);
                diagnostics.Add(file.Length == 0 ? message : $"{file}: {message}");
            }

            return new AnalyzerOutput(name, version, sourceDigest, source, verdicts, diagnostics);
        }
    }

    private static List<ReachPathEdge> ReadPath(JsonElement result)
    {
        List<ReachPathEdge> path = [];

        foreach (JsonElement edge in Array(result, "path").EnumerateArray())
        {
            if (path.Count >= MaxPathEdges)
            {
                throw Invalid("a path is longer than the protocol allows");
            }

            string kind = Str(edge, "kind", 16);

            if (kind is not ("static" or "dynamic"))
            {
                throw Invalid("unknown edge kind");
            }

            int? line = edge.TryGetProperty("line", out JsonElement l) && l.ValueKind == JsonValueKind.Number && l.TryGetInt32(out int n) ? n : null;
            path.Add(new ReachPathEdge(Str(edge, "from", 600), Str(edge, "to", 600), kind, OptionalStr(edge, "file", 300), line));
        }

        return path;
    }

    private static AnalyzerException Invalid(string what) => new($"the analyzer returned an invalid result: {what}.");

    private static JsonElement Object(JsonElement parent, string name) =>
        parent.ValueKind == JsonValueKind.Object && parent.TryGetProperty(name, out JsonElement e) && e.ValueKind == JsonValueKind.Object ? e : throw Invalid($"'{name}' is missing");

    private static JsonElement Array(JsonElement parent, string name) =>
        parent.ValueKind == JsonValueKind.Object && parent.TryGetProperty(name, out JsonElement e) && e.ValueKind == JsonValueKind.Array ? e : throw Invalid($"'{name}' is missing");

    private static int Int(JsonElement parent, string name) =>
        parent.ValueKind == JsonValueKind.Object && parent.TryGetProperty(name, out JsonElement e) && e.ValueKind == JsonValueKind.Number && e.TryGetInt32(out int n) && n >= 0
            ? n
            : throw Invalid($"'{name}' is missing");

    private static string Str(JsonElement parent, string name, int maxLength) =>
        OptionalStr(parent, name, maxLength) ?? throw Invalid($"'{name}' is missing");

    private static string? OptionalStr(JsonElement parent, string name, int maxLength)
    {
        if (parent.ValueKind != JsonValueKind.Object || !parent.TryGetProperty(name, out JsonElement e) || e.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (e.ValueKind != JsonValueKind.String || e.GetString() is not { } text || text.Length > maxLength)
        {
            throw Invalid($"'{name}' is not a short string");
        }

        return text;
    }
}
