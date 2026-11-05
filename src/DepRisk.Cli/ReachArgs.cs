using DepRisk.Core;
using DepRisk.Core.Reach;
using DepRisk.Data.Reach;

namespace DepRisk.Cli;

/// <summary>
/// The reachability options shared by <c>reach</c>, <c>rank</c>, and <c>ci</c>: <c>--symbols</c>, <c>--source</c>, <c>--analyzer</c>,
/// <c>--entrypoints</c>, <c>--entrypoint</c> (repeatable), <c>--timeout</c>.
/// </summary>
internal sealed class ReachArgs
{
    private const int DefaultTimeoutSeconds = 300;
    private const int MaxTimeoutSeconds = 3600;
    private static readonly string[] EntrypointModes = ["auto", "public-api", "none"];

    public string? Symbols { get; private set; }

    public string? Source { get; private set; }

    public string? Analyzer { get; private set; }

    public string Mode { get; private set; } = "auto";

    public List<string> ExplicitEntrypoints { get; } = [];

    public int TimeoutSeconds { get; private set; } = DefaultTimeoutSeconds;

    /// <summary>True if any reachability option was given (they all need <c>--symbols</c>).</summary>
    public bool AnyGiven { get; private set; }

    /// <summary>Reads the option at <paramref name="index"/> if it is a reachability option; returns whether it was.</summary>
    public bool TryRead(string[] args, ref int index, string arg)
    {
        if (TryValue(args, ref index, arg, "--symbols", "-s", out string? value))
        {
            Symbols = value;
        }
        else if (TryValue(args, ref index, arg, "--source", null, out value))
        {
            Source = value;
        }
        else if (TryValue(args, ref index, arg, "--analyzer", null, out value))
        {
            Analyzer = value;
        }
        else if (TryValue(args, ref index, arg, "--entrypoints", null, out value))
        {
            Mode = value!;
        }
        else if (TryValue(args, ref index, arg, "--entrypoint", null, out value))
        {
            ExplicitEntrypoints.Add(value!);
        }
        else if (TryValue(args, ref index, arg, "--timeout", null, out value))
        {
            if (!int.TryParse(value, out int seconds) || seconds < 1 || seconds > MaxTimeoutSeconds)
            {
                throw new InvalidInputException($"--timeout must be a whole number of seconds from 1 to {MaxTimeoutSeconds}.");
            }

            TimeoutSeconds = seconds;
        }
        else
        {
            return false;
        }

        AnyGiven = true;
        return true;
    }

    /// <summary>Checks the values. <paramref name="symbolsRequired"/> is true for <c>reach</c>; elsewhere the options are optional but depend on <c>--symbols</c>.</summary>
    public void Validate(string commandName, bool symbolsRequired)
    {
        if (!EntrypointModes.Contains(Mode, StringComparer.Ordinal))
        {
            throw new InvalidInputException($"--entrypoints must be one of: {string.Join(", ", EntrypointModes)}.");
        }

        foreach (string name in ExplicitEntrypoints)
        {
            if (!SymbolSyntax.IsValid(name) || name.EndsWith(".#ctor", StringComparison.Ordinal))
            {
                throw new InvalidInputException($"--entrypoint '{SafeText.Clean(name, 80)}' is not a method name (Namespace.Type.Method, or Namespace.Type.* for every member).");
            }
        }

        if (Symbols is null && symbolsRequired)
        {
            throw new InvalidInputException(
                $"'{commandName}' needs symbol maps: pass --symbols <file | directory> (docs/symbol-maps.md). OSV has no symbol data for NuGet, "
                + "so the symbols through which a flaw is reached must come from a symbol map.");
        }

        if (Symbols is null && AnyGiven)
        {
            throw new InvalidInputException(
                $"'{commandName}': --source, --analyzer, --entrypoints, --entrypoint, and --timeout only apply together with --symbols.");
        }
    }

    public ReachOptions ToOptions(string scanPath, string advisoriesPath, Ecosystem? ecosystem, bool strict, CliContext context) =>
        new(
            scanPath,
            advisoriesPath,
            Path.GetFullPath(Symbols!, context.WorkingDirectory),
            Source,
            ecosystem,
            strict,
            Mode,
            ExplicitEntrypoints,
            Analyzer,
            TimeSpan.FromSeconds(TimeoutSeconds),
            context.WorkingDirectory);

    internal static bool TryValue(string[] args, ref int index, string arg, string longName, string? shortName, out string? value)
    {
        value = null;

        if (arg == longName || (shortName is not null && arg == shortName))
        {
            if (index + 1 >= args.Length)
            {
                throw new InvalidInputException($"option '{arg}' needs a value.");
            }

            index++;
            value = args[index];
            return true;
        }

        if (arg.StartsWith(longName + "=", StringComparison.Ordinal))
        {
            value = arg[(longName.Length + 1)..];
            return true;
        }

        return false;
    }
}
