using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using DepRisk.Core;
using DepRisk.Data.Osv;
using Xunit;

namespace DepRisk.Data.Tests;

public sealed class AdvisorySnapshotLoaderTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-osv-" + Guid.NewGuid().ToString("N"));

    public AdvisorySnapshotLoaderTests() => Directory.CreateDirectory(_root);

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private string Dir(string name = "osv")
    {
        string path = Path.Combine(_root, name);
        Directory.CreateDirectory(path);
        return path;
    }

    private static void Write(string directory, string name, string content)
    {
        string path = Path.Combine(directory, name);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
    }

    private string Zip(string name, params (string Entry, string Content)[] entries)
    {
        string path = Path.Combine(_root, name);

        using (ZipArchive archive = ZipFile.Open(path, ZipArchiveMode.Create))
        {
            foreach ((string entryName, string content) in entries)
            {
                ZipArchiveEntry entry = archive.CreateEntry(entryName);
                using StreamWriter writer = new(entry.Open(), new UTF8Encoding(false));
                writer.Write(content);
            }
        }

        return path;
    }

    private string Mixed()
    {
        string dir = Dir("mixed");
        Write(dir, "GHSA-b.json", OsvFixtures.Make("GHSA-b", "Pkg.B", "0", "2.0.0"));
        Write(dir, "GHSA-a.json", OsvFixtures.Make("GHSA-a", "Pkg.A", "0", "1.0.0"));
        Write(dir, "nested/deep/GHSA-c.json", OsvFixtures.Make("GHSA-c", "Pkg.C", "1.0.0", null));
        Write(dir, "withdrawn.json", OsvFixtures.Withdrawn("GHSA-w"));
        Write(dir, "echo.json", OsvFixtures.OtherEcosystem("ECHO-1"));
        Write(dir, "broken.json", OsvFixtures.Garbage);
        Write(dir, "readme.txt", "not an advisory");
        return dir;
    }

    [Fact]
    public void A_directory_is_loaded_recursively_with_counts_and_sorted_advisories()
    {
        AdvisorySnapshot snapshot = AdvisorySnapshotLoader.Load(Mixed());

        Assert.Equal(new[] { "GHSA-a", "GHSA-b", "GHSA-c" }, snapshot.Advisories.Select(a => a.Id).ToArray());
        Assert.Equal(1, snapshot.SkippedWithdrawn);
        Assert.Equal(1, snapshot.SkippedNotNuGet);
        Assert.Equal(1, snapshot.SkippedInvalid);
        Assert.Equal("mixed", snapshot.Source);
        Assert.True(Digest.IsSha256Hex(snapshot.Digest));
        Assert.Contains("broken.json", Assert.Single(snapshot.InvalidSamples));
    }

    [Fact]
    public void The_digest_is_stable_and_changes_with_the_content()
    {
        string dir = Mixed();
        string first = AdvisorySnapshotLoader.Load(dir).Digest;

        Assert.Equal(first, AdvisorySnapshotLoader.Load(dir).Digest);

        Write(dir, "GHSA-a.json", OsvFixtures.Make("GHSA-a", "Pkg.A", "0", "1.0.1"));

        Assert.NotEqual(first, AdvisorySnapshotLoader.Load(dir).Digest);
    }

    [Fact]
    public void A_zip_is_loaded_without_extracting_and_its_digest_is_the_sha256_of_the_file()
    {
        string zip = Zip(
            "NuGet.zip",
            ("GHSA-a.json", OsvFixtures.Make("GHSA-a", "Pkg.A", "0", "1.0.0")),
            ("sub/GHSA-b.json", OsvFixtures.Make("GHSA-b", "Pkg.B", "0", "2.0.0")),
            ("withdrawn.json", OsvFixtures.Withdrawn("GHSA-w")),
            ("broken.json", OsvFixtures.Garbage),
            ("notes.txt", "ignored"));

        AdvisorySnapshot snapshot = AdvisorySnapshotLoader.Load(zip);

        Assert.Equal(new[] { "GHSA-a", "GHSA-b" }, snapshot.Advisories.Select(a => a.Id).ToArray());
        Assert.Equal(1, snapshot.SkippedWithdrawn);
        Assert.Equal(1, snapshot.SkippedInvalid);
        Assert.Equal("NuGet.zip", snapshot.Source);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(zip))), snapshot.Digest);
        Assert.False(Directory.Exists(Path.Combine(_root, "GHSA-a")));
    }

    [Fact]
    public void A_single_json_file_is_loaded()
    {
        string dir = Dir("single");
        Write(dir, "one.json", OsvFixtures.Typical);

        AdvisorySnapshot snapshot = AdvisorySnapshotLoader.Load(Path.Combine(dir, "one.json"));

        Assert.Equal("GHSA-test-aaaa-0001", Assert.Single(snapshot.Advisories).Id);
        Assert.Equal("one.json", snapshot.Source);
    }

    [Fact]
    public void Unsupported_missing_and_corrupt_sources_are_input_errors()
    {
        string text = Path.Combine(_root, "advisories.txt");
        File.WriteAllText(text, "x");
        string corrupt = Path.Combine(_root, "corrupt.zip");
        File.WriteAllText(corrupt, "this is not a zip file");

        Assert.Throws<InvalidInputException>(() => AdvisorySnapshotLoader.Load(text));
        Assert.Throws<InvalidInputException>(() => AdvisorySnapshotLoader.Load(Path.Combine(_root, "missing")));
        Assert.Throws<InvalidInputException>(() => AdvisorySnapshotLoader.Load(corrupt));
    }

    [Fact]
    public void An_entry_that_decompresses_to_more_than_the_limit_is_counted_invalid_and_does_not_exhaust_memory()
    {
        // 9 MiB of spaces compresses to a few KB: the declared size is irrelevant, the real size is enforced.
        string huge = "{\"id\":\"BOMB-1\"}" + new string(' ', 9 * 1024 * 1024);
        string zip = Zip("bomb.zip", ("bomb.json", huge), ("ok.json", OsvFixtures.Make("GHSA-ok", "Pkg", "0", "1.0.0")));

        AdvisorySnapshot snapshot = AdvisorySnapshotLoader.Load(zip);

        Assert.Equal("GHSA-ok", Assert.Single(snapshot.Advisories).Id);
        Assert.Equal(1, snapshot.SkippedInvalid);
        Assert.Contains("larger than", Assert.Single(snapshot.InvalidSamples));
    }

    [Fact]
    public void Oversized_files_in_a_directory_are_counted_invalid()
    {
        string dir = Dir("big");
        Write(dir, "big.json", "{\"id\":\"BIG-1\"}" + new string(' ', (int)AdvisorySnapshotLoader.MaxRecordBytes + 10));
        Write(dir, "ok.json", OsvFixtures.Make("GHSA-ok", "Pkg", "0", "1.0.0"));

        AdvisorySnapshot snapshot = AdvisorySnapshotLoader.Load(dir);

        Assert.Single(snapshot.Advisories);
        Assert.Equal(1, snapshot.SkippedInvalid);
    }

    [Fact]
    public void Only_a_few_invalid_samples_are_kept_but_all_are_counted()
    {
        string dir = Dir("many-broken");

        for (int i = 0; i < 12; i++)
        {
            Write(dir, $"broken-{i}.json", OsvFixtures.Garbage);
        }

        AdvisorySnapshot snapshot = AdvisorySnapshotLoader.Load(dir);

        Assert.Equal(12, snapshot.SkippedInvalid);
        Assert.Equal(AdvisorySnapshotLoader.MaxInvalidSamples, snapshot.InvalidSamples.Count);
    }

    [Fact]
    public void Symbolic_links_are_not_followed_out_of_the_directory()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        string outside = Dir("outside");
        Write(outside, "secret.json", OsvFixtures.Make("OUTSIDE-1", "Pkg.Out", "0", "1.0.0"));

        string inside = Dir("inside");
        Write(inside, "in.json", OsvFixtures.Make("INSIDE-1", "Pkg.In", "0", "1.0.0"));
        Directory.CreateSymbolicLink(Path.Combine(inside, "link"), outside);

        AdvisorySnapshot snapshot = AdvisorySnapshotLoader.Load(inside);

        Assert.Equal("INSIDE-1", Assert.Single(snapshot.Advisories).Id);
    }

    [Fact]
    public void An_empty_directory_gives_an_empty_snapshot()
    {
        AdvisorySnapshot snapshot = AdvisorySnapshotLoader.Load(Dir("empty"));

        Assert.Empty(snapshot.Advisories);
        Assert.Equal(0, snapshot.SkippedInvalid);
    }
}
