using DepRisk.Core;

namespace DepRisk.Cli;

/// <summary>
/// Reading the value of an option, the one way for every command: <c>--name value</c> or <c>--name=value</c> (and a short name where a command
/// has one). A missing value is an input error that names the option.
/// </summary>
internal static class OptionValue
{
    /// <summary>The value after the option at <paramref name="index"/>; moves the index to it.</summary>
    internal static string Read(string[] args, ref int index, string option)
    {
        if (index + 1 >= args.Length)
        {
            throw new InvalidInputException($"option '{option}' needs a value.");
        }

        index++;
        return args[index];
    }

    /// <summary>If <paramref name="arg"/> is this option (long name, short name, or <c>long=value</c>), reads its value and returns true.</summary>
    internal static bool TryValue(string[] args, ref int index, string arg, string longName, string? shortName, out string? value)
    {
        value = null;

        if (arg == longName || (shortName is not null && arg == shortName))
        {
            value = Read(args, ref index, arg);
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
