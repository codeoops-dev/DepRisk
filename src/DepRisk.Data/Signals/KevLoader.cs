using System.Text.Json;
using System.Text.RegularExpressions;
using DepRisk.Core;
using DepRisk.Core.Signals;

namespace DepRisk.Data.Signals;

/// <summary>
/// Loads the CISA Known Exploited Vulnerabilities catalog from a local JSON file
/// (<c>known_exploited_vulnerabilities.json</c>: envelope with catalogVersion and dateReleased, and a vulnerabilities array).
/// Unknown fields are ignored; entries without a valid CVE id are counted as skipped.
/// </summary>
public static partial class KevLoader
{
    public const long MaxBytes = 64L * 1024 * 1024;
    public const int MaxSamples = 5;

    private static readonly JsonDocumentOptions Options = new() { MaxDepth = 16 };

    public static KevData Load(string path)
    {
        ArgumentNullException.ThrowIfNull(path);

        string fullPath = Path.GetFullPath(path);

        if (!File.Exists(fullPath))
        {
            throw new InvalidInputException($"KEV file not found: {path}");
        }

        byte[] bytes;

        try
        {
            if (new FileInfo(fullPath).Length > MaxBytes)
            {
                throw new InvalidInputException($"KEV file is too large (limit {MaxBytes} bytes): {Path.GetFileName(fullPath)}");
            }

            bytes = File.ReadAllBytes(fullPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InvalidInputException($"cannot read the KEV file '{Path.GetFileName(fullPath)}' ({ex.Message})", ex);
        }

        return Parse(bytes, Path.GetFileName(fullPath), Digest.Sha256Hex(bytes));
    }

    public static KevData Parse(byte[] utf8Json, string source, string digest)
    {
        JsonDocument document;

        try
        {
            document = JsonDocument.Parse(utf8Json, Options);
        }
        catch (JsonException ex)
        {
            throw new InvalidInputException($"{source}: not valid JSON ({ex.Message})", ex);
        }

        using (document)
        {
            JsonElement root = document.RootElement;

            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("vulnerabilities", out JsonElement list)
                || list.ValueKind != JsonValueKind.Array)
            {
                throw new InvalidInputException($"{source}: not a KEV catalog (no 'vulnerabilities' array).");
            }

            string? version = ReadShortString(root, "catalogVersion");
            string? released = ReadShortString(root, "dateReleased");

            Dictionary<string, KevEntry> entries = new(StringComparer.Ordinal);
            List<string> samples = [];
            int skipped = 0;
            int index = 0;

            foreach (JsonElement item in list.EnumerateArray())
            {
                index++;
                string? cve = item.ValueKind == JsonValueKind.Object ? ReadShortString(item, "cveID") : null;

                if (cve is null || !CvePattern().IsMatch(cve))
                {
                    skipped++;

                    if (samples.Count < MaxSamples)
                    {
                        samples.Add($"{source}: entry {index}");
                    }

                    continue;
                }

                string normalized = cve.ToUpperInvariant();
                string? dateAdded = ReadShortString(item, "dateAdded");
                bool ransomware = string.Equals(ReadShortString(item, "knownRansomwareCampaignUse"), "Known", StringComparison.OrdinalIgnoreCase);

                entries[normalized] = new KevEntry(normalized, dateAdded, ransomware);
            }

            return new KevData(entries, version, released, source, digest, skipped, samples);
        }
    }

    private static string? ReadShortString(JsonElement element, string name)
    {
        if (element.TryGetProperty(name, out JsonElement property)
            && property.ValueKind == JsonValueKind.String
            && property.GetString() is { Length: > 0 and <= 64 } value)
        {
            return value;
        }

        return null;
    }

    [GeneratedRegex(@"^CVE-\d{4}-\d{4,}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CvePattern();
}
