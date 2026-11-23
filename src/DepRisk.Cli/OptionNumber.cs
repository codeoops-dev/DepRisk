using System.Globalization;

namespace DepRisk.Cli;

/// <summary>
/// Whole-number options, read one way in every command: invariant culture, an optional sign and surrounding spaces (as
/// <c>rank</c>, <c>ci</c>, <c>explain</c>, <c>vex</c> and <c>reach</c> always accepted), so that what any command accepted before is still
/// accepted and <c>bench</c> no longer rejects what the others take. Range checks stay with each option.
/// </summary>
internal static class OptionNumber
{
    internal static bool TryInt(string? text, out int value) =>
        int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);

    internal static bool TryULong(string? text, out ulong value) =>
        ulong.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
}
