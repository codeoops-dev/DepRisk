using DepRisk.Core;

namespace DepRisk.Cli;

/// <summary>
/// Entry point for command dispatch. Takes explicit writers so it can be tested without touching the console.
/// </summary>
internal static class CliApp
{
    public static int Run(string[] args, TextWriter output, TextWriter error)
    {
        try
        {
            return (int)Dispatch(args, output, error);
        }
        catch (Exception ex)
        {
            error.WriteLine($"{ProductInfo.CommandName}: internal error: {ex.GetType().Name}: {ex.Message}");

            if (Environment.GetEnvironmentVariable("DEPRISK_DEBUG") == "1")
            {
                error.WriteLine(ex.ToString());
            }

            return (int)ExitCode.InternalError;
        }
    }

    private static ExitCode Dispatch(string[] args, TextWriter output, TextWriter error)
    {
        if (args.Length == 0)
        {
            PrintUsage(output);
            return ExitCode.Success;
        }

        string command = args[0];

        switch (command)
        {
            case "-h":
            case "--help":
            case "help":
                PrintUsage(output);
                return ExitCode.Success;

            case "-v":
            case "--version":
            case "version":
                output.WriteLine($"{ProductInfo.CommandName} {VersionInfo.Current}");
                return ExitCode.Success;

            case "doctor":
                return DoctorCommand.Run(output);

            default:
                error.WriteLine($"{ProductInfo.CommandName}: unknown command '{command}'. Run '{ProductInfo.CommandName} --help'.");
                return ExitCode.InvalidInput;
        }
    }

    private static void PrintUsage(TextWriter output)
    {
        output.WriteLine($"{ProductInfo.Name} {VersionInfo.Current} (pre-alpha)");
        output.WriteLine();
        output.WriteLine("Usage:");
        output.WriteLine($"  {ProductInfo.CommandName} <command> [options]");
        output.WriteLine();
        output.WriteLine("Commands:");
        output.WriteLine("  doctor        Check that this installation is healthy");
        output.WriteLine("  version       Print the version");
        output.WriteLine("  help          Show this help");
        output.WriteLine();
        output.WriteLine("Planned commands (see the roadmap): init, scan, graph, reach, rank, plan, verify, apply, explain, vex, audit, bundle, bench, ci");
        output.WriteLine($"Documentation: {ProductInfo.RepositoryUrl}");
    }
}
