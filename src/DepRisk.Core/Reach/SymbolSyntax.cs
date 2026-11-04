namespace DepRisk.Core.Reach;

/// <summary>
/// The syntax of a C# symbol in a symbol map and in the analyzer protocol: dotted identifiers (ASCII letters, digits, and
/// underscore, not starting with a digit), at least a type and a member, where the last part may also be <c>*</c> (any member,
/// including constructors) or <c>#ctor</c> (the constructors). The same rule is enforced by the analyzer.
/// </summary>
public static class SymbolSyntax
{
    public const int MaxLength = 512;

    public static bool IsValid(string? symbol)
    {
        if (string.IsNullOrEmpty(symbol) || symbol.Length > MaxLength)
        {
            return false;
        }

        string[] parts = symbol.Split('.');

        if (parts.Length < 2)
        {
            return false;
        }

        string last = parts[^1];

        return (IsIdentifier(last) || last is "*" or "#ctor") && parts[..^1].All(IsIdentifier);
    }

    private static bool IsIdentifier(string part) =>
        part.Length > 0
        && (char.IsAsciiLetter(part[0]) || part[0] == '_')
        && part.All(c => char.IsAsciiLetterOrDigit(c) || c == '_');
}
