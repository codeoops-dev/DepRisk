using System.Text.Json;
using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Core.Reach;

namespace DepRisk.Data.Reach;

public sealed record LoadedSymbolMaps(SymbolMap Map, SymbolMapInfo Info);

/// <summary>
/// Reads symbol maps (docs/symbol-maps.md, schemas/symbol-map.v1.schema.json): a file, or a directory of <c>.json</c> files.
/// The input is untrusted data: bounded in size, depth, and count, strictly validated, and every problem is an
/// <see cref="InvalidInputException"/> that names the file and the entry. Nothing is skipped quietly: a symbol list that could
/// not be read must never turn into "no symbols known" without the user noticing.
/// </summary>
public static class SymbolMapLoader
{
    public const long MaxFileBytes = 16L * 1024 * 1024;
    public const int MaxFiles = 1000;
    public const int MaxEntries = 100_000;
    public const int MaxSymbolsPerEntry = 10_000;

    private static readonly JsonDocumentOptions DocumentOptions = new() { MaxDepth = 16, CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false };

    public static LoadedSymbolMaps Load(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        string fullPath = Path.GetFullPath(path);

        List<string> files;

        if (File.Exists(fullPath))
        {
            files = [fullPath];
        }
        else if (Directory.Exists(fullPath))
        {
            EnumerationOptions options = new()
            {
                RecurseSubdirectories = true,
                MaxRecursionDepth = 8,
                IgnoreInaccessible = true,
                AttributesToSkip = FileAttributes.ReparsePoint,
            };

            files = Directory.EnumerateFiles(fullPath, "*.json", options).Take(MaxFiles + 1).ToList();

            if (files.Count > MaxFiles)
            {
                throw new InvalidInputException($"too many symbol map files under '{path}' (limit {MaxFiles}).");
            }

            files.Sort(StringComparer.Ordinal);

            if (files.Count == 0)
            {
                throw new InvalidInputException($"no .json symbol map files found under '{path}'.");
            }
        }
        else
        {
            throw new InvalidInputException($"symbol maps not found: {path}");
        }

        List<SymbolSet> sets = [];
        List<string> digests = [];
        int entryCount = 0;

        foreach (string file in files)
        {
            string display = files.Count == 1 && File.Exists(fullPath) ? Path.GetFileName(file) : Path.GetRelativePath(fullPath, file).Replace('\\', '/');
            byte[] bytes = ReadBounded(file, display);
            digests.Add(Digest.Sha256Hex(bytes) + "  " + display);

            foreach (SymbolSet set in Parse(bytes, display))
            {
                sets.Add(set);
                entryCount++;

                if (entryCount > MaxEntries)
                {
                    throw new InvalidInputException($"more than {MaxEntries} symbol map entries (limit).");
                }
            }
        }

        digests.Sort(StringComparer.Ordinal);
        string source = File.Exists(fullPath) ? Path.GetFileName(fullPath) : Path.GetFileName(fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        SymbolMapInfo info = new(source, Digest.Sha256Hex(string.Join('\n', digests) + "\n"), files.Count, entryCount);

        return new LoadedSymbolMaps(new SymbolMap(sets), info);
    }

    private static byte[] ReadBounded(string file, string display)
    {
        try
        {
            FileInfo info = new(file);

            if (info.Length > MaxFileBytes)
            {
                throw new InvalidInputException($"{display}: larger than {MaxFileBytes / (1024 * 1024)} MB; not a symbol map.");
            }

            return File.ReadAllBytes(file);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InvalidInputException($"{display}: cannot be read ({ex.Message})", ex);
        }
    }

    private static IEnumerable<SymbolSet> Parse(byte[] bytes, string display)
    {
        JsonDocument document;

        try
        {
            document = JsonDocument.Parse(bytes, DocumentOptions);
        }
        catch (JsonException ex)
        {
            throw new InvalidInputException($"{display}: not valid JSON ({ex.Message})", ex);
        }

        using (document)
        {
            JsonElement root = document.RootElement;

            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("schemaVersion", out JsonElement version)
                || version.ValueKind != JsonValueKind.Number
                || !version.TryGetInt32(out int schemaVersion))
            {
                throw new InvalidInputException($"{display}: not a symbol map (missing 'schemaVersion').");
            }

            if (schemaVersion != 1)
            {
                throw new InvalidInputException($"{display}: unsupported schemaVersion {schemaVersion} (this version reads 1).");
            }

            if (!root.TryGetProperty("language", out JsonElement language) || language.ValueKind != JsonValueKind.String || language.GetString() != "csharp")
            {
                throw new InvalidInputException($"{display}: 'language' must be \"csharp\" (the only analyzer there is).");
            }

            if (!root.TryGetProperty("entries", out JsonElement entries) || entries.ValueKind != JsonValueKind.Array)
            {
                throw new InvalidInputException($"{display}: 'entries' must be an array.");
            }

            List<SymbolSet> sets = [];
            int index = 0;

            foreach (JsonElement entry in entries.EnumerateArray())
            {
                if (sets.Count >= MaxEntries)
                {
                    throw new InvalidInputException($"{display}: more than {MaxEntries} entries (limit).");
                }

                sets.Add(ReadEntry(entry, display, index));
                index++;
            }

            return sets;
        }
    }

    private static SymbolSet ReadEntry(JsonElement entry, string display, int index)
    {
        string where = $"{display}: entry {index}";

        if (entry.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidInputException($"{where} is not an object.");
        }

        string advisory = RequiredString(entry, "advisory", where, 100, IsAdvisoryChar);
        string package = RequiredString(entry, "package", where, 200, IsPackageChar);
        string source = RequiredString(entry, "source", where, 500, c => !char.IsControl(c));

        // Required on purpose: whoever writes a symbol list must decide whether it claims to be complete. There is no default.
        if (!entry.TryGetProperty("complete", out JsonElement complete) || complete.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw new InvalidInputException($"{where} ('{SafeText.Clean(advisory, 60)}') needs 'complete': true or false (is this list every public way to reach the flaw?).");
        }

        if (!entry.TryGetProperty("symbols", out JsonElement symbols) || symbols.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidInputException($"{where} needs a 'symbols' array.");
        }

        List<string> list = [];

        foreach (JsonElement symbol in symbols.EnumerateArray())
        {
            string? text = symbol.ValueKind == JsonValueKind.String ? symbol.GetString() : null;

            if (!SymbolSyntax.IsValid(text))
            {
                throw new InvalidInputException(
                    $"{where}: '{SafeText.Clean(text ?? "(not a string)", 80)}' is not a valid symbol (Namespace.Type.Member, Namespace.Type.#ctor, or Namespace.Type.*).");
            }

            list.Add(text!);

            if (list.Count > MaxSymbolsPerEntry)
            {
                throw new InvalidInputException($"{where}: more than {MaxSymbolsPerEntry} symbols (limit).");
            }
        }

        if (list.Count == 0)
        {
            throw new InvalidInputException($"{where}: 'symbols' is empty. An entry without symbols says nothing; remove it.");
        }

        return new SymbolSet(advisory, package, list.Distinct(StringComparer.Ordinal).OrderBy(s => s, StringComparer.Ordinal).ToList(), complete.GetBoolean(), [source]);
    }

    private static string RequiredString(JsonElement entry, string name, string where, int maxLength, Func<char, bool> allowed)
    {
        if (!entry.TryGetProperty(name, out JsonElement element) || element.ValueKind != JsonValueKind.String || element.GetString() is not { Length: > 0 } value)
        {
            throw new InvalidInputException($"{where} needs a non-empty '{name}'.");
        }

        if (value.Length > maxLength || !value.All(allowed))
        {
            throw new InvalidInputException($"{where}: invalid '{name}'.");
        }

        return value;
    }

    private static bool IsAdvisoryChar(char c) => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or ':' or '-';

    private static bool IsPackageChar(char c) => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-';
}
