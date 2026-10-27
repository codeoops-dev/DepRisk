using Xunit;
using DepRisk.Core;

namespace DepRisk.Cli.Tests;

public class CliAppTests
{
    private static (int Code, string Out, string Err) Run(params string[] args)
    {
        using StringWriter output = new();
        using StringWriter error = new();
        int code = CliApp.Run(args, output, error);
        return (code, output.ToString(), error.ToString());
    }

    [Theory]
    [InlineData("--version")]
    [InlineData("-v")]
    [InlineData("version")]
    public void Version_prints_name_and_semver(string flag)
    {
        (int code, string output, string error) = Run(flag);

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Matches(@"^deprisk \d+\.\d+\.\d+(-[0-9A-Za-z.\-]+)?\r?\n$", output);
        Assert.Equal(string.Empty, error);
    }

    [Theory]
    [InlineData("--help")]
    [InlineData("-h")]
    [InlineData("help")]
    public void Help_lists_commands_and_succeeds(string flag)
    {
        (int code, string output, _) = Run(flag);

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("doctor", output);
    }

    [Fact]
    public void No_arguments_prints_usage()
    {
        (int code, string output, _) = Run();

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("Usage:", output);
    }

    [Fact]
    public void Unknown_command_is_an_input_error()
    {
        (int code, string output, string error) = Run("frobnicate");

        Assert.Equal((int)ExitCode.InvalidInput, code);
        Assert.Equal(string.Empty, output);
        Assert.Contains("unknown command 'frobnicate'", error);
    }

    [Fact]
    public void Doctor_succeeds_and_reports_the_version()
    {
        (int code, string output, string error) = Run("doctor");

        Assert.Equal((int)ExitCode.Success, code);
        Assert.Contains("deprisk doctor", output);
        Assert.Contains("version", output);
        Assert.Equal(string.Empty, error);
    }
}
