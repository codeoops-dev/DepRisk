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

            case "graph":
                return GraphCommand.Run(args[1..], output, context);

            case "match":
                return MatchCommand.Run(args[1..], output, context);

            case "reach":
                return ReachCommand.Run(args[1..], output, context);

            case "explain":
                return ExplainCommand.Run(args[1..], output, context);

            case "vex":
                return VexCommand.Run(args[1..], output, context);

            case "bench":
                return BenchCommand.Run(args[1..], output, context);

            case "rank":
                return RankCommand.Run(args[1..], output, context);

            case "ci":
                return RankCommand.Run(args[1..], output, error, context, "ci", ci: true);

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
        output.WriteLine("  scan [path]   Read the restored dependency graph: NuGet (project.assets.json) or npm (package-lock.json)");
        output.WriteLine("                  --ecosystem auto|nuget|npm   what to read (default: auto, from the files found)");
        output.WriteLine("                  --format table|json   output format (default: table)");
        output.WriteLine("                  --out <file>          write the result to a file");
        output.WriteLine("  graph [path]  Dependency hypergraph of the resolved graph; checks every requirement (NuGet and npm)");
        output.WriteLine("                  --format table|json|dot  --out <file>  --ecosystem auto|nuget|npm");
        output.WriteLine("  match [path]  Match dependencies against local OSV advisories (offline)");
        output.WriteLine("                  --advisories <dir|.zip|.json>   advisory data (required)");
        output.WriteLine("                  --format table|json  --out <file>  --strict  --ecosystem auto|nuget|npm");
        output.WriteLine("  reach [path]  Can the vulnerable code be reached from your application? (C#, needs symbol maps and the analyzer)");
        output.WriteLine("                  --advisories <...>  --symbols <file|dir>  --source <dir>  --entrypoints auto|public-api|none");
        output.WriteLine("                  --entrypoint <Ns.Type.Method>  --analyzer <file>  --timeout <seconds>  --format table|json  --out <file>");
        output.WriteLine("  explain <id> [path]  Why a finding stands where it does: evidence, reachability path, risk, what would change it");
        output.WriteLine("                  --advisories <...>  --package <id>  (analysis options as for rank)  --format table|json  --out <file>");
        output.WriteLine("  vex [path]    OpenVEX 0.2.0 statements for the findings (not_affected only for proven unreachable ones)");
        output.WriteLine("                  --product <purl|iri>  --author <text>  [--role <text>]  [--timestamp <rfc3339>]  (analysis options)  --out <file>");
        output.WriteLine("  rank [path]   Like match, ordered by CISA KEV, EPSS, and CVSS (baseline; offline)");
        output.WriteLine("                  --advisories <...> (required)  --epss <csv[.gz]>  --kev <json>");
        output.WriteLine("                  --format table|json|sarif  --out <file>  --strict  --ecosystem auto|nuget|npm");
        output.WriteLine("                  --symbols <file|dir> (adds reachability; also --source --analyzer --entrypoints --entrypoint --timeout)");
        output.WriteLine("                  --model baseline|risk (risk: seeded Monte Carlo; also --samples --seed --rank-by mean|p50|p90|p95|cvar95 --risk-params <file>)");
        output.WriteLine("  ci [path]     Like rank, plus a policy gate: exit code 1 if a finding matches --fail-on");
        output.WriteLine("                  --fail-on \"kev&fixable,cvss>=9\"  (terms: any kev ransomware direct fixable cvss>=N epss>=P severity>=LEVEL)");
        output.WriteLine("                  --format table|json|sarif  --out <file>  (verdict is printed on standard error)");
        output.WriteLine("  bench --cases <manifest.json>  Compare the baselines (B1 CVSS, B2 KEV/EPSS/CVSS, B3 reachable-only) with the risk model on labeled cases");
        output.WriteLine("                  --split dev|test|all  --samples <n>  --seed <n>  --rank-by <stat>  --risk-params <file>  --bootstrap <n>  --analyzer <file>");
        output.WriteLine("                  --timeout <seconds>  --strict  --format table|json  --out <file>");
        output.WriteLine("  bench calibrate --cases <manifest.json> --out <risk-params.json>  Fit the Reach factor on the dev split (--prior uniform|current, --min-count <n>, --risk-params <file>)");
        output.WriteLine("  audit verify  Verify the audit log (--pubkey <file>, --head <hash>)");
        output.WriteLine("  doctor        Check that this installation is healthy");
        output.WriteLine("  version       Print the version");
        output.WriteLine("  help          Show this help");
        output.WriteLine();
        output.WriteLine("Planned commands (see the roadmap): plan, verify, apply, bundle");
        output.WriteLine($"Documentation: {ProductInfo.RepositoryUrl}");
    }
}
