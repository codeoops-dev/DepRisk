using DepRisk.Data.Reach;
using Xunit;

namespace DepRisk.Data.Tests;

/// <summary>The real process runner, with small shell scripts. Unix only: on Windows the CLI tests cover the runner with a .cmd script.</summary>
public sealed class AnalyzerProcessTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "deprisk-proc-" + Guid.NewGuid().ToString("N"));

    public AnalyzerProcessTests() => Directory.CreateDirectory(_root);

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private string Script(string body)
    {
        string path = Path.Combine(_root, "analyzer.sh");
        File.WriteAllText(path, "#!/bin/sh\n" + body + "\n");
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return path;
    }

    [Fact]
    public void The_request_goes_in_on_stdin_and_the_result_and_exit_code_come_back()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        AnalyzerRun run = new AnalyzerProcess().Run(Script("cat; echo; echo problem >&2; exit 7"), "{\"hello\":\"world\"}", TimeSpan.FromSeconds(10));

        Assert.Equal(7, run.ExitCode);
        Assert.Contains("{\"hello\":\"world\"}", run.StdOut);
        Assert.Contains("problem", run.StdErr);
    }

    [Fact]
    public void An_analyzer_that_never_reads_its_input_does_not_hang_or_fail_the_run()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        string bigRequest = new('x', 8 * 1024 * 1024);

        AnalyzerRun run = new AnalyzerProcess().Run(Script("echo done"), bigRequest, TimeSpan.FromSeconds(20));

        Assert.Equal(0, run.ExitCode);
        Assert.Contains("done", run.StdOut);
    }

    [Fact]
    public void A_run_that_takes_too_long_is_stopped_with_a_clear_message()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        AnalyzerException error = Assert.Throws<AnalyzerException>(
            () => new AnalyzerProcess().Run(Script("sleep 30"), "{}", TimeSpan.FromSeconds(1)));

        Assert.Contains("did not finish within 1 s", error.Message);
        Assert.Contains("--timeout", error.Message);
    }

    [Fact]
    public void An_executable_that_cannot_be_started_is_an_analyzer_error()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        string notExecutable = Path.Combine(_root, "plain.txt");
        File.WriteAllText(notExecutable, "just text");

        Assert.Throws<AnalyzerException>(() => new AnalyzerProcess().Run(notExecutable, "{}", TimeSpan.FromSeconds(5)));
    }
}
