using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using DepRisk.Core;

namespace DepRisk.Data.Bench;

/// <summary>Ground truth for one finding of a case, keyed by advisory (id or alias) and package id.</summary>
public sealed record BenchLabel(string Advisory, string Package, bool Exploited, bool? Reachable);

/// <summary>One case: a project, the data it is analyzed with, and the ground truth. Paths are absolute and verified to lie inside the manifest directory.</summary>
public sealed record BenchCase(
    string Id,
    string Split,
    string ScanPath,
    string AdvisoriesPath,
    string? EpssPath,
    string? KevPath,
    string? SymbolsPath,
    string? SourcePath,
    Ecosystem? Ecosystem,
    string EntrypointMode,
    IReadOnlyList<string> Entrypoints,
    IReadOnlyList<BenchLabel> Labels);

public sealed record BenchManifest(
    string Name,
    string? Description,
    bool Synthetic,
    DateOnly SignalsAsOf,
    DateOnly OutcomeFrom,
    DateOnly OutcomeTo,
    string LabelSource,
    IReadOnlyList<BenchCase> Cases);

public sealed record LoadedBenchManifest(BenchManifest Manifest, string Root, string Digest);

/// <summary>
/// Reads a benchmark manifest (schemas/bench-manifest.v1.schema.json, docs/benchmarks.md). The manifest is untrusted input: strict
/// (an unknown property is an error), bounded, and every path must be relative, exist, and stay inside the manifest's directory without
/// passing through a symbolic link. Nothing it names is executed.
/// </summary>
public static partial class BenchManifestLoader
{
    public const long MaxFileBytes = 16L * 1024 * 1024;
    public const int MaxCases = 5000;
    public const int MaxLabelsPerCase = 100_000;
    public const int MaxLabelsTotal = 500_000;

    private const int MaxText = 200;
    private const int MaxPath = 260;
    private static readonly JsonDocumentOptions DocumentOptions = new() { MaxDepth = 16, CommentHandling = JsonCommentHandling.Disallow };
    private static readonly string[] EntrypointModes = ["auto", "public-api", "none"];

    public static LoadedBenchManifest Load(string manifestPath)
    {
        ArgumentNullException.ThrowIfNull(manifestPath);

        string full = Path.GetFullPath(manifestPath);

        if (!File.Exists(full))
        {
            throw new InvalidInputException($"benchmark manifest not found: {SafeText.Clean(manifestPath, 200)}");
        }

        string name = Path.GetFileName(full);
        byte[] bytes;

        try
        {
            if (new FileInfo(full).Length > MaxFileBytes)
            {
                throw new InvalidInputException($"{name}: larger than 16 MB; not a benchmark manifest.");
            }

            bytes = File.ReadAllBytes(full);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InvalidInputException($"{name}: cannot be read ({ex.Message})", ex);
        }

        JsonDocument document;

        try
        {
            document = JsonDocument.Parse(bytes, DocumentOptions);
        }
        catch (JsonException ex)
        {
            throw new InvalidInputException($"{name}: not valid JSON ({ex.Message})", ex);
        }

        using (document)
        {
            string root = Path.GetDirectoryName(full)!;
            BenchManifest manifest = Parse(document.RootElement, root, name);
            return new LoadedBenchManifest(manifest, root, Digest.Sha256Hex(bytes));
        }
    }

    private static BenchManifest Parse(JsonElement root, string directory, string file)
    {
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("schemaVersion", out JsonElement version) || !version.TryGetInt32(out int v))
        {
            throw new InvalidInputException($"{file}: not a benchmark manifest (missing 'schemaVersion').");
        }

        if (v != 1)
        {
            throw new InvalidInputException($"{file}: unsupported schemaVersion {v} (this version reads 1).");
        }

        RequireKnown(root, ["schemaVersion", "name", "description", "synthetic", "signalsAsOf", "outcomeWindow", "labelSource", "cases"], "the file", file);

        string name = RequiredText(root, "name", "the file", file);
        string? description = OptionalText(root, "description", "the file", file);
        bool synthetic = RequiredBool(root, "synthetic", "the file", file);
        DateOnly asOf = RequiredDate(root, "signalsAsOf", "the file", file);
        string labelSource = RequiredText(root, "labelSource", "the file", file);

        JsonElement window = RequiredObject(root, "outcomeWindow", "the file", file);
        RequireKnown(window, ["from", "to"], "outcomeWindow", file);
        DateOnly from = RequiredDate(window, "from", "outcomeWindow", file);
        DateOnly to = RequiredDate(window, "to", "outcomeWindow", file);

        // The temporal split that keeps the evaluation honest: signals are those known at asOf, outcomes are observed afterwards.
        if (from < asOf)
        {
            throw new InvalidInputException($"{file}: outcomeWindow.from ({from:yyyy-MM-dd}) is before signalsAsOf ({asOf:yyyy-MM-dd}); outcomes must be observed after the signals were fixed.");
        }

        if (to <= from)
        {
            throw new InvalidInputException($"{file}: outcomeWindow.to must be after outcomeWindow.from.");
        }

        if (!root.TryGetProperty("cases", out JsonElement casesElement) || casesElement.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidInputException($"{file}: 'cases' must be an array.");
        }

        if (casesElement.GetArrayLength() is 0 or > MaxCases)
        {
            throw new InvalidInputException($"{file}: 'cases' must hold 1 to {MaxCases} cases.");
        }

        List<BenchCase> cases = [];
        HashSet<string> ids = new(StringComparer.Ordinal);
        int labelsTotal = 0;

        foreach (JsonElement element in casesElement.EnumerateArray())
        {
            BenchCase parsed = ParseCase(element, directory, file);

            if (!ids.Add(parsed.Id))
            {
                throw new InvalidInputException($"{file}: case id '{parsed.Id}' appears twice.");
            }

            labelsTotal += parsed.Labels.Count;

            if (labelsTotal > MaxLabelsTotal)
            {
                throw new InvalidInputException($"{file}: more than {MaxLabelsTotal} labels in total.");
            }

            cases.Add(parsed);
        }

        return new BenchManifest(name, description, synthetic, asOf, from, to, labelSource, cases);
    }

    private static BenchCase ParseCase(JsonElement element, string directory, string file)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidInputException($"{file}: every case must be an object.");
        }

        RequireKnown(
            element,
            ["id", "split", "path", "advisories", "epss", "kev", "symbols", "source", "ecosystem", "entrypoints", "entrypointNames", "labels"],
            "a case",
            file);

        string id = RequiredText(element, "id", "a case", file);

        if (!IdPattern().IsMatch(id))
        {
            throw new InvalidInputException($"{file}: case id '{SafeText.Clean(id, 40)}' must be 1 to 64 characters from A-Z a-z 0-9 . _ -.");
        }

        string where = $"case '{id}'";
        string split = RequiredText(element, "split", where, file);

        if (split is not ("dev" or "test"))
        {
            throw new InvalidInputException($"{file}: {where}: 'split' must be 'dev' or 'test'.");
        }

        string scan = ResolveInside(directory, RequiredText(element, "path", where, file, MaxPath), "path", where, file);
        string advisories = ResolveInside(directory, RequiredText(element, "advisories", where, file, MaxPath), "advisories", where, file);
        string? epss = OptionalPath(element, "epss", directory, where, file);
        string? kev = OptionalPath(element, "kev", directory, where, file);
        string? symbols = OptionalPath(element, "symbols", directory, where, file);
        string? source = OptionalPath(element, "source", directory, where, file);

        Ecosystem? ecosystem = null;

        if (OptionalText(element, "ecosystem", where, file) is { } ecosystemId)
        {
            if (!Ecosystem.TryFromId(ecosystemId, out ecosystem))
            {
                throw new InvalidInputException($"{file}: {where}: ecosystem '{SafeText.Clean(ecosystemId, 20)}' is not supported (supported: {string.Join(", ", Ecosystem.All.Select(e => e.Id))}).");
            }
        }

        string mode = OptionalText(element, "entrypoints", where, file) ?? "auto";

        if (!EntrypointModes.Contains(mode, StringComparer.Ordinal))
        {
            throw new InvalidInputException($"{file}: {where}: 'entrypoints' must be one of: {string.Join(", ", EntrypointModes)}.");
        }

        List<string> names = [];

        if (element.TryGetProperty("entrypointNames", out JsonElement namesElement))
        {
            if (namesElement.ValueKind != JsonValueKind.Array || namesElement.GetArrayLength() > 100)
            {
                throw new InvalidInputException($"{file}: {where}: 'entrypointNames' must be an array of at most 100 names.");
            }

            foreach (JsonElement name in namesElement.EnumerateArray())
            {
                names.Add(name.ValueKind == JsonValueKind.String ? Text(name.GetString()!, "entrypointNames", where, file) : throw new InvalidInputException($"{file}: {where}: 'entrypointNames' must hold strings."));
            }
        }

        if (symbols is null && (source is not null || names.Count > 0 || element.TryGetProperty("entrypoints", out _)))
        {
            throw new InvalidInputException($"{file}: {where}: 'source', 'entrypoints', and 'entrypointNames' only apply together with 'symbols'.");
        }

        if (!element.TryGetProperty("labels", out JsonElement labelsElement) || labelsElement.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidInputException($"{file}: {where}: 'labels' must be an array.");
        }

        if (labelsElement.GetArrayLength() > MaxLabelsPerCase)
        {
            throw new InvalidInputException($"{file}: {where}: more than {MaxLabelsPerCase} labels.");
        }

        List<BenchLabel> labels = [];
        HashSet<string> keys = new(StringComparer.OrdinalIgnoreCase);

        foreach (JsonElement labelElement in labelsElement.EnumerateArray())
        {
            if (labelElement.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidInputException($"{file}: {where}: every label must be an object.");
            }

            RequireKnown(labelElement, ["advisory", "package", "exploited", "reachable"], "a label", file);

            string advisory = RequiredText(labelElement, "advisory", "a label", file);
            string package = RequiredText(labelElement, "package", "a label", file);
            bool exploited = RequiredBool(labelElement, "exploited", "a label", file);
            bool? reachable = null;

            if (labelElement.TryGetProperty("reachable", out JsonElement reachableElement) && reachableElement.ValueKind != JsonValueKind.Null)
            {
                reachable = reachableElement.ValueKind is JsonValueKind.True or JsonValueKind.False
                    ? reachableElement.GetBoolean()
                    : throw new InvalidInputException($"{file}: a label's 'reachable' must be true, false, or null.");
            }

            if (!keys.Add(advisory + "|" + package))
            {
                throw new InvalidInputException($"{file}: {where}: the label for '{SafeText.Clean(advisory, 60)}' and '{SafeText.Clean(package, 60)}' appears twice.");
            }

            labels.Add(new BenchLabel(advisory, package, exploited, reachable));
        }

        return new BenchCase(id, split, scan, advisories, epss, kev, symbols, source, ecosystem, mode, names, labels);
    }

    private static string? OptionalPath(JsonElement element, string property, string directory, string where, string file)
    {
        string? relative = OptionalText(element, property, where, file, MaxPath);
        return relative is null ? null : ResolveInside(directory, relative, property, where, file);
    }

    /// <summary>
    /// Resolves a manifest path: relative, existing, inside the manifest directory, and not reached through a symbolic link (no part of
    /// the path may be one), so that a manifest cannot make the tool read or analyze files elsewhere.
    /// </summary>
    internal static string ResolveInside(string directory, string relative, string property, string where, string file)
    {
        string shown = SafeText.Clean(relative, 80);

        if (Path.IsPathRooted(relative) || relative.StartsWith('/') || relative.StartsWith('\\'))
        {
            throw new InvalidInputException($"{file}: {where}: '{property}' ({shown}) must be a relative path.");
        }

        string full = Path.GetFullPath(Path.Combine(directory, relative));
        StringComparison comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        string prefix = directory.EndsWith(Path.DirectorySeparatorChar) ? directory : directory + Path.DirectorySeparatorChar;

        if (!full.StartsWith(prefix, comparison))
        {
            throw new InvalidInputException($"{file}: {where}: '{property}' ({shown}) leaves the directory of the manifest.");
        }

        if (!File.Exists(full) && !Directory.Exists(full))
        {
            throw new InvalidInputException($"{file}: {where}: '{property}' ({shown}) does not exist.");
        }

        // No component below the manifest directory may be a link.
        string current = directory;

        foreach (string part in full[prefix.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, part);
            FileSystemInfo info = Directory.Exists(current) ? new DirectoryInfo(current) : new FileInfo(current);

            if (info.LinkTarget is not null)
            {
                throw new InvalidInputException($"{file}: {where}: '{property}' ({shown}) passes through a symbolic link; links are not followed.");
            }
        }

        return full;
    }

    private static void RequireKnown(JsonElement element, string[] known, string where, string file)
    {
        foreach (JsonProperty property in element.EnumerateObject())
        {
            if (!known.Contains(property.Name, StringComparer.Ordinal))
            {
                throw new InvalidInputException($"{file}: unknown property '{SafeText.Clean(property.Name, 40)}' in {where}.");
            }
        }
    }

    private static JsonElement RequiredObject(JsonElement element, string property, string where, string file) =>
        element.TryGetProperty(property, out JsonElement value) && value.ValueKind == JsonValueKind.Object
            ? value
            : throw new InvalidInputException($"{file}: '{property}' in {where} must be an object.");

    private static string RequiredText(JsonElement element, string property, string where, string file, int max = MaxText) =>
        OptionalText(element, property, where, file, max) ?? throw new InvalidInputException($"{file}: '{property}' is required in {where}.");

    private static string? OptionalText(JsonElement element, string property, string where, string file, int max = MaxText)
    {
        if (!element.TryGetProperty(property, out JsonElement value) || value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (value.ValueKind != JsonValueKind.String)
        {
            throw new InvalidInputException($"{file}: '{property}' in {where} must be a string.");
        }

        return Text(value.GetString()!, property, where, file, max);
    }

    private static string Text(string text, string property, string where, string file, int max = MaxText)
    {
        if (text.Length == 0 || text.Length > max || text.Any(char.IsControl))
        {
            throw new InvalidInputException($"{file}: '{property}' in {where} must be 1 to {max} characters without control characters.");
        }

        return text;
    }

    private static bool RequiredBool(JsonElement element, string property, string where, string file) =>
        element.TryGetProperty(property, out JsonElement value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? value.GetBoolean()
            : throw new InvalidInputException($"{file}: '{property}' in {where} must be true or false.");

    private static DateOnly RequiredDate(JsonElement element, string property, string where, string file)
    {
        string text = RequiredText(element, property, where, file, 10);

        return DateOnly.TryParseExact(text, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateOnly date)
            ? date
            : throw new InvalidInputException($"{file}: '{property}' in {where} must be a date as yyyy-MM-dd.");
    }

    [GeneratedRegex(@"^[A-Za-z0-9._-]{1,64}$", RegexOptions.CultureInvariant)]
    private static partial Regex IdPattern();
}
