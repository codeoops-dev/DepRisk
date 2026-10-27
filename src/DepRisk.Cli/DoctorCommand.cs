using System.Runtime.InteropServices;
using DepRisk.Core;

namespace DepRisk.Cli;

/// <summary>
/// Diagnoses the installation. At this stage it only reports facts; it never changes anything
/// and makes no network calls.
/// </summary>
internal static class DoctorCommand
{
    private enum Status
    {
        Ok,
        Info,
        Warn,
    }

    private sealed record Check(Status Status, string Name, string Detail);

    public static ExitCode Run(TextWriter output)
    {
        List<Check> checks =
        [
            new(Status.Ok, "version", VersionInfo.Current),
            new(Status.Ok, "runtime", RuntimeInformation.FrameworkDescription),
            new(Status.Ok, "platform", $"{RuntimeInformation.OSDescription} ({RuntimeInformation.OSArchitecture})"),
            CheckCompanion("deprisk-reach", "reachability analyzer (planned, v0.2)"),
            CheckCompanion("deprisk-kernel", "verification kernel (planned, v0.4)"),
            CheckConfig(),
        ];

        output.WriteLine($"{ProductInfo.CommandName} doctor");
        output.WriteLine();

        foreach (Check check in checks)
        {
            string tag = check.Status switch
            {
                Status.Ok => " ok ",
                Status.Info => "info",
                _ => "warn",
            };

            output.WriteLine($"  [{tag}] {check.Name,-16} {check.Detail}");
        }

        int warnings = checks.Count(c => c.Status == Status.Warn);
        output.WriteLine();
        output.WriteLine(warnings == 0 ? "No problems found." : $"{warnings} warning(s).");

        // Warnings never fail the command at this stage; hard failures will be added with the components they cover.
        return ExitCode.Success;
    }

    private static Check CheckCompanion(string name, string description)
    {
        string? path = FindExecutable(name);

        return path is null
            ? new Check(Status.Info, name, $"not installed: {description}")
            : new Check(Status.Ok, name, path);
    }

    private static Check CheckConfig()
    {
        string path = Path.Combine(Directory.GetCurrentDirectory(), "deprisk.toml");

        return File.Exists(path)
            ? new Check(Status.Ok, "config", path)
            : new Check(Status.Info, "config", "deprisk.toml not found in the current directory (optional at this stage)");
    }

    private static string? FindExecutable(string name)
    {
        string[] candidates = OperatingSystem.IsWindows() ? [name + ".exe", name] : [name];

        List<string> directories = [AppContext.BaseDirectory];
        string? pathVariable = Environment.GetEnvironmentVariable("PATH");

        if (!string.IsNullOrEmpty(pathVariable))
        {
            directories.AddRange(pathVariable.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries));
        }

        foreach (string directory in directories)
        {
            foreach (string candidate in candidates)
            {
                try
                {
                    string full = Path.Combine(directory, candidate);

                    if (File.Exists(full))
                    {
                        return full;
                    }
                }
                catch (ArgumentException)
                {
                    // Malformed PATH entry: ignore it.
                }
            }
        }

        return null;
    }
}
