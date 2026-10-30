using DepRisk.Core;

namespace DepRisk.Cli;

/// <summary>Text from untrusted data made safe to print on a terminal. See <see cref="SafeText"/>.</summary>
internal static class TerminalText
{
    public static string Safe(string? text, int maxLength) => SafeText.Clean(text, maxLength);
}
