using System.IO.Compression;
using System.IO.Enumeration;
using System.Security.Cryptography;
using System.Text;
using DepRisk.Core;
using DepRisk.Core.Advisories;

namespace DepRisk.Data.Osv;

/// <summary>
/// Loads OSV advisories from a directory of <c>*.json</c> files, a <c>.zip</c> of them (for example OSV's per-ecosystem
/// dump <c>NuGet/all.zip</c>), or a single <c>.json</c> file. Works offline. The data is untrusted, so every limit below
/// is enforced while reading, and zip entries are read in memory and never extracted to disk.
/// </summary>
public static class AdvisorySnapshotLoader
{
    public const int MaxRecords = 1_000_000;
    public const long MaxRecordBytes = 8L * 1024 * 1024;
    public const long MaxTotalBytes = 2L * 1024 * 1024 * 1024;
    public const int MaxInvalidSamples = 5;
    private const int MaxDirectoryDepth = 16;

    public static AdvisorySnapshot Load(string path)
    {
        ArgumentNullException.ThrowIfNull(path);

        string fullPath = Path.GetFullPath(path);

        if (File.Exists(fullPath))
        {
            string extension = Path.GetExtension(fullPath);

            if (extension.Equals(".zip", StringComparison.OrdinalIgnoreCase))
            {
                return LoadZip(fullPath);
            }

            if (extension.Equals(".json", StringComparison.OrdinalIgnoreCase))
            {
                return LoadFiles(fullPath, [fullPath], singleFile: true);
            }

            throw new InvalidInputException(
                $"'{path}' is not a supported advisory source (expected a directory of .json files, a .zip, or a single .json file).");
        }

        if (!Directory.Exists(fullPath))
        {
            throw new InvalidInputException($"advisory source not found: {path}");
        }

        return LoadFiles(fullPath, FindJsonFiles(fullPath, path), singleFile: false);
    }

    private static List<string> FindJsonFiles(string directory, string displayPath)
    {
        EnumerationOptions options = new()
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            MaxRecursionDepth = MaxDirectoryDepth,
            AttributesToSkip = FileAttributes.ReparsePoint,
        };

        FileSystemEnumerable<string> enumerable = new(
            directory,
            static (ref FileSystemEntry entry) => entry.ToFullPath(),
            options)
        {
            ShouldIncludePredicate = static (ref FileSystemEntry entry) =>
                !entry.IsDirectory && entry.FileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase),
        };

        List<string> files = enumerable.Take(MaxRecords + 1).ToList();

        if (files.Count > MaxRecords)
        {
            throw new InvalidInputException($"too many advisory files under '{displayPath}' (limit {MaxRecords}).");
        }

        files.Sort(StringComparer.Ordinal);
        return files;
    }

    private static AdvisorySnapshot LoadFiles(string root, List<string> files, bool singleFile)
    {
        Collector collector = new();
        StringBuilder digestInput = new();
        string baseDirectory = singleFile ? Path.GetDirectoryName(root) ?? root : root;

        foreach (string file in files)
        {
            string display = Path.GetRelativePath(baseDirectory, file).Replace('\\', '/');
            byte[] bytes;

            try
            {
                long length = new FileInfo(file).Length;

                if (length > MaxRecordBytes)
                {
                    collector.AddInvalid($"{display}: file is too large ({length} bytes; limit {MaxRecordBytes})");
                    continue;
                }

                bytes = File.ReadAllBytes(file);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new InvalidInputException($"{display}: cannot read advisory file ({ex.Message})", ex);
            }

            collector.AddBytes(bytes.Length);
            digestInput.Append(Digest.Sha256Hex(bytes)).Append("  ").Append(display).Append('\n');
            collector.Add(display, bytes);
        }

        string source = singleFile ? Path.GetFileName(root) : Path.GetFileName(root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        return collector.ToSnapshot(string.IsNullOrEmpty(source) ? "advisories" : source, Digest.Sha256Hex(digestInput.ToString()));
    }

    private static AdvisorySnapshot LoadZip(string zipPath)
    {
        Collector collector = new();
        string digest;

        try
        {
            using (FileStream hashStream = File.OpenRead(zipPath))
            {
                digest = Convert.ToHexStringLower(SHA256.HashData(hashStream));
            }

            using FileStream stream = File.OpenRead(zipPath);
            using ZipArchive archive = new(stream, ZipArchiveMode.Read);

            if (archive.Entries.Count > MaxRecords)
            {
                throw new InvalidInputException($"the advisory archive has too many entries ({archive.Entries.Count}; limit {MaxRecords}).");
            }

            foreach (ZipArchiveEntry entry in archive.Entries)
            {
                if (!entry.FullName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                string display = Sanitize(entry.FullName);
                byte[]? bytes = ReadBounded(entry, collector, display);

                if (bytes is not null)
                {
                    collector.Add(display, bytes);
                }
            }
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or UnauthorizedAccessException)
        {
            throw new InvalidInputException($"cannot read the advisory archive '{Path.GetFileName(zipPath)}' ({ex.Message})", ex);
        }

        return collector.ToSnapshot(Path.GetFileName(zipPath), digest);
    }

    /// <summary>Reads at most <see cref="MaxRecordBytes"/> from an entry, never trusting the size the archive declares.</summary>
    private static byte[]? ReadBounded(ZipArchiveEntry entry, Collector collector, string display)
    {
        using Stream input = entry.Open();
        using MemoryStream buffer = new();
        byte[] chunk = new byte[81920];
        long total = 0;

        while (true)
        {
            int read = input.Read(chunk, 0, chunk.Length);

            if (read == 0)
            {
                break;
            }

            total += read;

            if (total > MaxRecordBytes)
            {
                collector.AddInvalid($"{display}: entry is larger than {MaxRecordBytes} bytes when decompressed");
                collector.AddBytes(MaxRecordBytes);
                return null;
            }

            buffer.Write(chunk, 0, read);
        }

        collector.AddBytes(total);
        return buffer.ToArray();
    }

    private static string Sanitize(string name)
    {
        string cleaned = new(name.Select(c => char.IsControl(c) ? '?' : c).ToArray());
        return cleaned.Length > 200 ? cleaned[..200] + "…" : cleaned;
    }

    private sealed class Collector
    {
        private readonly List<Advisory> _advisories = [];
        private readonly List<string> _invalidSamples = [];
        private long _totalBytes;
        private int _withdrawn;
        private int _notNuGet;
        private int _invalid;

        public void AddBytes(long bytes)
        {
            _totalBytes += bytes;

            if (_totalBytes > MaxTotalBytes)
            {
                throw new InvalidInputException($"the advisory data is larger than the {MaxTotalBytes / (1024 * 1024)} MiB limit.");
            }
        }

        public void AddInvalid(string message)
        {
            _invalid++;

            if (_invalidSamples.Count < MaxInvalidSamples)
            {
                _invalidSamples.Add(message);
            }
        }

        public void Add(string display, byte[] bytes)
        {
            OsvParseResult result = OsvParser.Parse(bytes);

            switch (result.Status)
            {
                case OsvParseStatus.Ok:
                    _advisories.Add(result.Advisory!);
                    break;
                case OsvParseStatus.Withdrawn:
                    _withdrawn++;
                    break;
                case OsvParseStatus.NotNuGet:
                    _notNuGet++;
                    break;
                default:
                    AddInvalid($"{display}: {result.Error}");
                    break;
            }
        }

        public AdvisorySnapshot ToSnapshot(string source, string digest) =>
            new(
                _advisories.OrderBy(a => a.Id, StringComparer.Ordinal).ToList(),
                source,
                digest,
                _withdrawn,
                _notNuGet,
                _invalid,
                _invalidSamples);
    }
}
