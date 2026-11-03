using DepRisk.Core;

namespace DepRisk.Cli;

/// <summary>The <c>--ecosystem nuget|npm|auto</c> option shared by the commands that read dependency files.</summary>
internal static class EcosystemOption
{
    public const string Name = "--ecosystem";

    /// <summary>Usage text for the option (one line, for help output).</summary>
    public const string Usage = "--ecosystem auto|nuget|npm   what to read (default: auto, from the files found)";

    /// <returns>The ecosystem, or null for "auto" (detect from the files found).</returns>
    public static Ecosystem? Parse(string value, string command)
    {
        if (value == "auto")
        {
            return null;
        }

        if (Ecosystem.TryFromId(value, out Ecosystem? ecosystem))
        {
            return ecosystem;
        }

        throw new InvalidInputException(
            $"ecosystem '{value}' is not supported for '{command}' (supported: auto, {string.Join(", ", Ecosystem.All.Select(e => e.Id))}).");
    }
}
