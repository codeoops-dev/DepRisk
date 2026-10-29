using System.IO.Compression;
using System.Text;
using DepRisk.Core;
using DepRisk.Core.Signals;
using DepRisk.Data.Signals;
using Xunit;

namespace DepRisk.Data.Tests;

public sealed class SignalLoaderTests : IDisposable
{
    private const string EpssCsv =
        "#model_version:v2025.03.14,score_date:2026-10-20T12:55:00Z\n"
        + "cve,epss,percentile\n"
        + "CVE-2025-0001,0.97321,0.99876\n"
        + "CVE-2024-12345,0.00042,0.05\n"
        + "cve-2023-0007,0.5,0.9\n";

    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-signals-" + Guid.NewGuid().ToString("N"));

    public SignalLoaderTests() => Directory.CreateDirectory(_root);

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private string Write(string name, string content)
    {
        string path = Path.Combine(_root, name);
        File.WriteAllText(path, content, new UTF8Encoding(false));
        return path;
    }

    private string WriteGzip(string name, string content)
    {
        string path = Path.Combine(_root, name);

        using (FileStream file = File.Create(path))
        using (GZipStream gzip = new(file, CompressionLevel.Optimal))
        {
            byte[] bytes = Encoding.UTF8.GetBytes(content);
            gzip.Write(bytes, 0, bytes.Length);
        }

        return path;
    }

    // ---- EPSS ----

    [Fact]
    public void Epss_csv_is_read_with_metadata_and_normalized_cve_ids()
    {
        EpssData data = EpssLoader.Load(Write("epss.csv", EpssCsv));

        Assert.Equal(3, data.Scores.Count);
        Assert.Equal(0.97321, data.Scores["CVE-2025-0001"].Probability);
        Assert.Equal(0.99876, data.Scores["CVE-2025-0001"].Percentile);
        Assert.True(data.Scores.ContainsKey("CVE-2023-0007"));
        Assert.Equal("v2025.03.14", data.ModelVersion);
        Assert.Equal("2026-10-20T12:55:00Z", data.ScoreDate);
        Assert.Equal("epss.csv", data.Source);
        Assert.Equal(0, data.SkippedRows);
        Assert.True(Digest.IsSha256Hex(data.Digest));
    }

    [Fact]
    public void A_gzip_file_gives_the_same_scores_and_digests_the_supplied_bytes()
    {
        string plain = Write("epss.csv", EpssCsv);
        string gz = WriteGzip("epss.csv.gz", EpssCsv);

        EpssData fromPlain = EpssLoader.Load(plain);
        EpssData fromGzip = EpssLoader.Load(gz);

        Assert.Equal(fromPlain.Scores.Count, fromGzip.Scores.Count);
        Assert.Equal(fromPlain.ModelVersion, fromGzip.ModelVersion);
        Assert.Equal(Digest.Sha256Hex(File.ReadAllBytes(gz)), fromGzip.Digest);
        Assert.NotEqual(fromPlain.Digest, fromGzip.Digest);
    }

    [Fact]
    public void The_metadata_comment_is_optional_and_crlf_line_endings_work()
    {
        EpssData data = EpssLoader.Load(Write("epss.csv", "cve,epss,percentile\r\nCVE-2025-0001,0.5,0.6\r\n"));

        Assert.Single(data.Scores);
        Assert.Null(data.ModelVersion);
        Assert.Null(data.ScoreDate);
    }

    [Fact]
    public void A_byte_order_mark_is_tolerated()
    {
        string path = Path.Combine(_root, "bom.csv");
        File.WriteAllText(path, "cve,epss,percentile\nCVE-2025-0001,0.5,0.6\n", new UTF8Encoding(true));

        Assert.Single(EpssLoader.Load(path).Scores);
    }

    [Fact]
    public void Malformed_rows_are_counted_and_the_rest_is_kept()
    {
        string csv = "cve,epss,percentile\n"
            + "CVE-2025-0001,0.5,0.6\n"
            + "not-a-cve,0.5,0.6\n"
            + "CVE-2025-0002,1.5,0.6\n"
            + "CVE-2025-0003,abc,0.6\n"
            + "CVE-2025-0004,0.5\n"
            + "CVE-2025-0005,NaN,0.1\n"
            + "CVE-2025-0006,-0.1,0.1\n";

        EpssData data = EpssLoader.Load(Write("epss.csv", csv));

        Assert.Single(data.Scores);
        Assert.Equal(6, data.SkippedRows);
        Assert.Equal(EpssLoader.MaxSamples, data.SkippedSamples.Count);
        Assert.Contains("line 3", data.SkippedSamples[0]);
    }

    [Fact]
    public void Probabilities_are_parsed_with_the_invariant_culture()
    {
        System.Globalization.CultureInfo original = System.Globalization.CultureInfo.CurrentCulture;

        try
        {
            System.Globalization.CultureInfo.CurrentCulture = new System.Globalization.CultureInfo("fa-IR");

            EpssData data = EpssLoader.Load(Write("epss.csv", EpssCsv));

            Assert.Equal(0.97321, data.Scores["CVE-2025-0001"].Probability);
        }
        finally
        {
            System.Globalization.CultureInfo.CurrentCulture = original;
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("this is not epss data\n")]
    [InlineData("#model_version:v1\n")]
    [InlineData("cve;epss;percentile\nCVE-2025-0001;0.5;0.6\n")]
    public void Files_without_the_epss_header_are_input_errors(string content)
    {
        Assert.Throws<InvalidInputException>(() => EpssLoader.Load(Write("bad.csv", content)));
    }

    [Fact]
    public void Missing_and_corrupt_gzip_files_are_input_errors()
    {
        string corrupt = Path.Combine(_root, "corrupt.csv.gz");
        File.WriteAllBytes(corrupt, [0x1f, 0x8b, 0x08, 0x00, 0x01, 0x02, 0x03]);

        Assert.Throws<InvalidInputException>(() => EpssLoader.Load(Path.Combine(_root, "missing.csv")));
        Assert.Throws<InvalidInputException>(() => EpssLoader.Load(corrupt));
    }

    [Fact]
    public void A_gzip_bomb_is_stopped_by_the_decompressed_size_limit()
    {
        // About 600 MiB of zeros compresses to well under a megabyte. The limit applies to the real decompressed bytes.
        string path = Path.Combine(_root, "bomb.csv.gz");

        using (FileStream file = File.Create(path))
        using (GZipStream gzip = new(file, CompressionLevel.SmallestSize))
        {
            byte[] header = Encoding.UTF8.GetBytes("cve,epss,percentile\n");
            gzip.Write(header, 0, header.Length);
            byte[] block = new byte[1024 * 1024];

            for (int i = 0; i < 600; i++)
            {
                gzip.Write(block, 0, block.Length);
            }
        }

        Assert.True(new FileInfo(path).Length < 5 * 1024 * 1024);

        InvalidInputException error = Assert.Throws<InvalidInputException>(() => EpssLoader.Load(path));
        Assert.Contains("larger than", error.Message);
    }

    // ---- KEV ----

    private const string KevJson = """
    {
      "title": "CISA Catalog of Known Exploited Vulnerabilities",
      "catalogVersion": "2026.10.20",
      "dateReleased": "2026-10-20T15:01:52.9591Z",
      "count": 3,
      "vulnerabilities": [
        { "cveID": "CVE-2025-0001", "vendorProject": "V", "product": "P", "dateAdded": "2025-05-01",
          "knownRansomwareCampaignUse": "Known", "notes": "https://example.invalid", "cwes": ["CWE-1"], "futureField": 1 },
        { "cveID": "cve-2024-12345", "dateAdded": "2024-01-02", "knownRansomwareCampaignUse": "Unknown" },
        { "cveID": "CVE-2023-0007" }
      ]
    }
    """;

    [Fact]
    public void Kev_json_is_read_with_flags_and_metadata_and_unknown_fields_are_ignored()
    {
        string path = Write("kev.json", KevJson);

        KevData data = KevLoader.Load(path);

        Assert.Equal(3, data.Entries.Count);
        Assert.True(data.Entries["CVE-2025-0001"].KnownRansomwareUse);
        Assert.Equal("2025-05-01", data.Entries["CVE-2025-0001"].DateAdded);
        Assert.False(data.Entries["CVE-2024-12345"].KnownRansomwareUse);
        Assert.Null(data.Entries["CVE-2023-0007"].DateAdded);
        Assert.Equal("2026.10.20", data.CatalogVersion);
        Assert.Equal("2026-10-20T15:01:52.9591Z", data.DateReleased);
        Assert.Equal("kev.json", data.Source);
        Assert.Equal(Digest.Sha256Hex(File.ReadAllBytes(path)), data.Digest);
        Assert.Equal(0, data.SkippedEntries);
    }

    [Fact]
    public void Kev_entries_without_a_valid_cve_are_counted()
    {
        KevData data = KevLoader.Load(Write("kev.json", """
            { "vulnerabilities": [ { "cveID": "CVE-2025-0001" }, { "cveID": "nope" }, { "dateAdded": "x" }, 5, { "cveID": 7 } ] }
            """));

        Assert.Single(data.Entries);
        Assert.Equal(4, data.SkippedEntries);
        Assert.Equal(4, data.SkippedSamples.Count);
    }

    [Theory]
    [InlineData("{ not json")]
    [InlineData("[]")]
    [InlineData("{ \"title\": \"no list\" }")]
    [InlineData("{ \"vulnerabilities\": 5 }")]
    public void Files_that_are_not_a_kev_catalog_are_input_errors(string content)
    {
        Assert.Throws<InvalidInputException>(() => KevLoader.Load(Write("bad.json", content)));
    }

    [Fact]
    public void A_missing_kev_file_is_an_input_error()
    {
        Assert.Throws<InvalidInputException>(() => KevLoader.Load(Path.Combine(_root, "missing.json")));
    }

    [Fact]
    public void Overlong_metadata_strings_are_dropped_not_printed()
    {
        KevData data = KevLoader.Load(Write("kev.json", $$"""
            { "catalogVersion": "{{new string('x', 500)}}", "vulnerabilities": [] }
            """));

        Assert.Null(data.CatalogVersion);
    }
}
