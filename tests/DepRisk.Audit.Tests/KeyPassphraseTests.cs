using System.Text;
using Xunit;

namespace DepRisk.Audit.Tests;

public sealed class KeyPassphraseTests : IDisposable
{
    private const string Secret = "correct horse battery staple";

    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-passphrase-" + Guid.NewGuid().ToString("N"));

    public KeyPassphraseTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private static Func<string, string?> Env(params (string Name, string Value)[] variables) =>
        name => variables.Where(v => v.Name == name).Select(v => v.Value).FirstOrDefault();

    private string File_(string name, byte[] content)
    {
        string path = Path.Combine(_root, name);
        File.WriteAllBytes(path, content);
        return path;
    }

    [Fact]
    public void Neither_variable_set_is_no_passphrase()
    {
        Assert.Null(KeyPassphrase.Read(Env(), _root));
    }

    [Fact]
    public void The_variable_is_the_passphrase_exactly_as_it_is()
    {
        Assert.Equal(" " + Secret + " ", KeyPassphrase.Read(Env((KeyPassphrase.EnvironmentVariable, " " + Secret + " ")), _root));
    }

    [Theory]
    [InlineData("secret\n", "secret")]
    [InlineData("secret\r\n", "secret")]
    [InlineData("secret", "secret")]
    [InlineData("with spaces inside\n", "with spaces inside")]
    [InlineData("\uFEFFwith bom\n", "with bom")]
    [InlineData("pässwörd-ünïcode\n", "pässwörd-ünïcode")]
    public void The_file_holds_one_line_with_or_without_its_line_ending(string content, string expected)
    {
        string file = File_("pass.txt", new UTF8Encoding(false).GetBytes(content));

        Assert.Equal(expected, KeyPassphrase.Read(Env((KeyPassphrase.FileEnvironmentVariable, file)), "/elsewhere"));
    }

    [Fact]
    public void A_full_path_does_not_depend_on_the_directory_it_is_given()
    {
        string file = File_("pass.txt", Encoding.UTF8.GetBytes(Secret));

        // A base that is not fully qualified is refused by Path.GetFullPath(path, basePath) on every system (on Windows "/work" is one).
        Assert.Equal(Secret, KeyPassphrase.Read(Env((KeyPassphrase.FileEnvironmentVariable, file)), "not-a-full-path"));
        Assert.Equal(Secret, KeyPassphrase.Read(Env((KeyPassphrase.FileEnvironmentVariable, file)), Path.DirectorySeparatorChar + "work"));
    }

    [Fact]
    public void A_relative_file_is_found_from_the_given_directory()
    {
        File_("rel.txt", Encoding.UTF8.GetBytes(Secret));

        Assert.Equal(Secret, KeyPassphrase.Read(Env((KeyPassphrase.FileEnvironmentVariable, "rel.txt")), _root));
    }

    [Fact]
    public void Both_variables_are_an_error_that_does_not_show_either_value()
    {
        string file = File_("pass.txt", Encoding.UTF8.GetBytes(Secret));

        AuditException error = Assert.Throws<AuditException>(
            () => KeyPassphrase.Read(Env((KeyPassphrase.EnvironmentVariable, "another passphrase"), (KeyPassphrase.FileEnvironmentVariable, file)), _root));

        Assert.Contains("use one", error.Message);
        Assert.DoesNotContain("another passphrase", error.Message);
        Assert.DoesNotContain(Secret, error.Message);
    }

    [Theory]
    [InlineData("DEPRISK_KEY_PASSPHRASE")]
    [InlineData("DEPRISK_KEY_PASSPHRASE_FILE")]
    public void A_variable_that_is_set_but_empty_is_an_error(string name)
    {
        AuditException error = Assert.Throws<AuditException>(() => KeyPassphrase.Read(Env((name, string.Empty)), _root));

        Assert.Contains("set but empty", error.Message);
    }

    [Fact]
    public void A_file_that_cannot_be_the_passphrase_is_an_error_that_does_not_show_its_content()
    {
        string multiline = File_("multi.txt", Encoding.UTF8.GetBytes(Secret + "\nsecond line\n"));
        string empty = File_("empty.txt", []);
        string onlyNewline = File_("newline.txt", Encoding.UTF8.GetBytes("\n"));
        string large = File_("large.txt", Encoding.UTF8.GetBytes(new string('x', 2000)));
        string notUtf8 = File_("bad.txt", [0xFF, 0xFE, 0xFD, 0x80]);

        foreach ((string file, string expected) in new[]
        {
            (multiline, "must hold one line"),
            (empty, "is empty"),
            (onlyNewline, "is empty"),
            (large, "larger than"),
            (notUtf8, "not valid UTF-8"),
            (Path.Combine(_root, "missing.txt"), "does not exist"),
        })
        {
            AuditException error = Assert.Throws<AuditException>(() => KeyPassphrase.Read(Env((KeyPassphrase.FileEnvironmentVariable, file)), _root));

            Assert.Contains(expected, error.Message);
            Assert.DoesNotContain(Secret, error.Message);
            Assert.DoesNotContain("second line", error.Message);
        }
    }
}
