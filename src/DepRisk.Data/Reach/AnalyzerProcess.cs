using System.Diagnostics;
using System.Text;

namespace DepRisk.Data.Reach;

public sealed record AnalyzerRun(int ExitCode, string StdOut, string StdErr);

/// <summary>Runs the analyzer: one request in, one result out. A seam so that tests can use a fake.</summary>
public interface IAnalyzerProcess
{
    AnalyzerRun Run(string executable, string requestJson, TimeSpan timeout);
}

/// <summary>
/// Starts the analyzer as a child process: no shell, no arguments, the request on stdin, the result read from stdout with a size
/// limit, a time limit that kills the whole process tree. Nothing from the environment of the analyzer is trusted: its output is
/// validated by <see cref="ReachProtocol"/> before anything is used.
/// </summary>
public sealed class AnalyzerProcess : IAnalyzerProcess
{
    public const int MaxOutputChars = 64 * 1024 * 1024;
    private const int MaxErrorChars = 8 * 1024;

    public AnalyzerRun Run(string executable, string requestJson, TimeSpan timeout)
    {
        ProcessStartInfo start = new(executable)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardInputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };

        using Process process = new() { StartInfo = start };

        try
        {
            process.Start();
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            throw new AnalyzerException($"cannot start the analyzer ({ex.Message})", ex);
        }

        Task<string> stdout = Task.Run(() => ReadLimited(process.StandardOutput, MaxOutputChars));
        Task<string> stderr = Task.Run(() => ReadLimited(process.StandardError, MaxErrorChars));

        try
        {
            process.StandardInput.Write(requestJson);
            process.StandardInput.Close();
        }
        catch (IOException)
        {
            // The analyzer may exit without reading everything (for example on an invalid request); its exit code says why.
        }

        if (!process.WaitForExit(timeout))
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                // Already gone.
            }

            throw new AnalyzerException($"the analyzer did not finish within {(int)timeout.TotalSeconds} s and was stopped (raise --timeout, or analyze less code with --source).");
        }

        process.WaitForExit();

        return new AnalyzerRun(process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult());
    }

    /// <summary>Reads at most <paramref name="limit"/> characters, and keeps draining the stream so that the child never blocks.</summary>
    private static string ReadLimited(StreamReader reader, int limit)
    {
        StringBuilder builder = new();
        char[] buffer = new char[8192];
        int read;

        while ((read = reader.Read(buffer, 0, buffer.Length)) > 0)
        {
            if (builder.Length <= limit)
            {
                builder.Append(buffer, 0, Math.Min(read, limit + 1 - builder.Length));
            }
        }

        return builder.ToString();
    }
}
