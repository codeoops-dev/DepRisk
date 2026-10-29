using DepRisk.Audit;
using DepRisk.Core;

namespace DepRisk.Cli;

/// <summary>
/// Entry point for command dispatch. Takes explicit writers so it can be tested without touching the console.
/// </summary>
internal static class CliApp
{
    public static int Run(string[] args, TextWriter output, TextWriter error) =>
        Run(args, output, error, CliContext.Default());

    public static int Run(string[] args, TextWriter output, TextWriter error, CliContext context)
    {
        try
        {
            return (int)Dispatch(args, output, error, context);
        }
        catch (AuditException ex)
        {
            error.WriteLine($"{ProductInfo.CommandName}: audit: {ex.Message}");
            return (int)ExitCode.AuditIntegrityFailure;
        }
        catch (InvalidInputException ex)
        {
            error.WriteLine($"{ProductInfo.CommandName}: {ex.Message}");
            return (int)ExitCode.InvalidInput;
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

    private static ExitCode Dispatch(string[] args, TextWriter output, TextWriter error, CliContext context)
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
                return DoctorCommand.Run(output, context);

            case "init":
                return InitCommand.Run(args[1..], output, context);

            case "scan":
                return ScanCommand.Run(args[1..], output, context);

            case "match":
                return MatchCommand.Run(args[1..], output, context);

            case "rank":
                return RankCommand.Run(args[1..], output, context);

            case "audit":
                return AuditCommand.Run(args[1..], output, error, context);

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
        output.WriteLine("  init [path]   Start a signed audit log in this project (creates .deprisk/)");
        output.WriteLine("  scan [path]   Read the restored NuGet dependency graph (project.assets.json)");
        output.WriteLine("                  --format table|json   output format (default: table)");
        output.WriteLine("                  --out <file>          write the result to a file");
        output.WriteLine("  match [path]  Match dependencies against local OSV advisories (offline)");
        output.WriteLine("                  --advisories <dir|.zip|.json>   advisory data (required)");
        output.WriteLine("                  --format table|json  --out <file>  --strict");
        output.WriteLine("  rank [path]   Like match, ordered by CISA KEV, EPSS, and CVSS (baseline; offline)");
        output.WriteLine("                  --advisories <...> (required)  --epss <csv[.gz]>  --kev <json>");
        output.WriteLine("                  --format table|json  --out <file>  --strict");
        output.WriteLine("  audit verify  Verify the audit log (--pubkey <file>, --head <hash>)");
        output.WriteLine("  doctor        Check that this installation is healthy");
        output.WriteLine("  version       Print the version");
        output.WriteLine("  help          Show this help");
        output.WriteLine();
        output.WriteLine("Planned commands (see the roadmap): graph, reach, plan, verify, apply, explain, vex, bundle, bench, ci");
        output.WriteLine($"Documentation: {ProductInfo.RepositoryUrl}");
    }
}
