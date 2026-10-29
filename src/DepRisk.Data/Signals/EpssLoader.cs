using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using DepRisk.Core;
using DepRisk.Core.Signals;

namespace DepRisk.Data.Signals;

/// <summary>
/// Loads FIRST's EPSS data from a local file: the published <c>epss_scores-*.csv</c> or <c>.csv.gz</c>.
/// Format: an optional first line starting with '#' (model version and score date), the header <c>cve,epss,percentile</c>,
/// then one row per CVE. Input is untrusted: sizes are bounded on the real decompressed bytes and malformed rows are
/// counted rather than silently ignored.
/// </summary>
public static partial class EpssLoader
{
    public const long MaxBytes = 512L * 1024 * 1024;
    public const int MaxSamples = 5;

    public static EpssData Load(string path)
    {
        ArgumentNullException.ThrowIfNull(path);

        string fullPath = Path.GetFullPath(path);

        if (!File.Exists(fullPath))
        {
            throw new InvalidInputException($"EPSS file not found: {path}");
        }

        byte[] raw;

        try
        {
            if (new FileInfo(fullPath).Length > MaxBytes)
            {
                throw new InvalidInputException($"EPSS file is too large (limit {MaxBytes} bytes): {Path.GetFileName(fullPath)}");
            }

            raw = File.ReadAllBytes(fullPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InvalidInputException($"cannot read the EPSS file '{Path.GetFileName(fullPath)}' ({ex.Message})", ex);
        }

        string digest = Digest.Sha256Hex(raw);
        string text = DecodeBounded(raw, fullPath);
        return Parse(text, Path.GetFileName(fullPath), digest);
    }

    /// <summary>Parses EPSS CSV text. Public so tests and callers with in-memory data can use it.</summary>
    public static EpssData Parse(string text, string source, string digest)
    {
        ArgumentNullException.ThrowIfNull(text);

        Dictionary<string, EpssScore> scores = new(StringComparer.Ordinal);
        List<string> samples = [];
        string? modelVersion = null;
        string? scoreDate = null;
        bool headerSeen = false;
        int skipped = 0;
        int lineNumber = 0;

        foreach (string rawLine in text.Split('\n'))
        {
            lineNumber++;
            string line = rawLine.Trim();

            if (line.Length == 0)
            {
                continue;
            }

            if (line[0] == '#')
            {
                (modelVersion, scoreDate) = ReadComment(line, modelVersion, scoreDate);
                continue;
            }

            if (!headerSeen)
            {
                if (!line.Equals("cve,epss,percentile", StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidInputException(
                        $"{source}: line {lineNumber} is not the EPSS header 'cve,epss,percentile' (is this an EPSS file?).");
                }

                headerSeen = true;
                continue;
            }

            string[] fields = line.Split(',');

            if (fields.Length != 3
                || !CvePattern().IsMatch(fields[0])
                || !TryProbability(fields[1], out double probability)
                || !TryProbability(fields[2], out double percentile))
            {
                skipped++;

                if (samples.Count < MaxSamples)
                {
                    samples.Add($"{source}: line {lineNumber}");
                }

                continue;
            }

            scores[fields[0].ToUpperInvariant()] = new EpssScore(probability, percentile);
        }

        if (!headerSeen)
        {
            throw new InvalidInputException($"{source}: no EPSS header 'cve,epss,percentile' found (is this an EPSS file?).");
        }

        return new EpssData(scores, modelVersion, scoreDate, source, digest, skipped, samples);
    }

    private static string DecodeBounded(byte[] raw, string fullPath)
    {
        bool gzip = raw.Length >= 2 && raw[0] == 0x1f && raw[1] == 0x8b;
        using MemoryStream source = new(raw);
        using Stream input = gzip ? new GZipStream(source, CompressionMode.Decompress) : source;
        using MemoryStream buffer = new();
        byte[] chunk = new byte[81920];
        long total = 0;

        try
        {
            while (true)
            {
                int read = input.Read(chunk, 0, chunk.Length);

                if (read == 0)
                {
                    break;
                }

                total += read;

                if (total > MaxBytes)
                {
                    throw new InvalidInputException($"EPSS data in '{Path.GetFileName(fullPath)}' is larger than {MaxBytes} bytes when decompressed.");
                }

                buffer.Write(chunk, 0, read);
            }
        }
        catch (InvalidDataException ex)
        {
            throw new InvalidInputException($"'{Path.GetFileName(fullPath)}' is not a valid gzip file ({ex.Message})", ex);
        }

        return new UTF8Encoding(false).GetString(buffer.GetBuffer(), 0, (int)buffer.Length).TrimStart('\uFEFF');
    }

    private static (string? Model, string? Date) ReadComment(string line, string? model, string? date)
    {
        // Example: #model_version:v2025.03.14,score_date:2025-03-14T12:55:00Z
        foreach (string part in line.TrimStart('#').Split(','))
        {
            int colon = part.IndexOf(':', StringComparison.Ordinal);

            if (colon <= 0)
            {
                continue;
            }

            string key = part[..colon].Trim();
            string value = part[(colon + 1)..].Trim();

            if (key.Equals("model_version", StringComparison.OrdinalIgnoreCase) && value.Length <= 64)
            {
                model = value;
            }
            else if (key.Equals("score_date", StringComparison.OrdinalIgnoreCase) && value.Length <= 64)
            {
                date = value;
            }
        }

        return (model, date);
    }

    private static bool TryProbability(string text, out double value) =>
        double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out value)
        && value is >= 0 and <= 1
        && double.IsFinite(value);

    [GeneratedRegex(@"^CVE-\d{4}-\d{4,}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CvePattern();
}
