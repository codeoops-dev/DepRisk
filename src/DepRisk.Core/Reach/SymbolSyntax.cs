namespace DepRisk.Core.Reach;

/// <summary>The languages of symbol maps and of the analyzer.</summary>
public static class SymbolLanguages
{
    public const string CSharp = "csharp";
    public const string JavaScript = "javascript";

    public static bool IsKnown(string? language) => language is CSharp or JavaScript;
}

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

    // ---- JavaScript and TypeScript (ADR 0019, ADR 0020) ----------------------------------------------------------------------

    /// <summary>
    /// A JavaScript package specifier as an npm package name, possibly with a subpath: <c>lodash</c>, <c>@scope/pkg</c>,
    /// <c>lodash/fp</c>. Never relative or absolute.
    /// </summary>
    public static bool IsValidJsPackage(string? package) =>
        !string.IsNullOrEmpty(package)
        && package.Length <= 214
        && package[0] is not ('.' or '/')
        && !package.Contains("..", StringComparison.Ordinal)
        && !package.Contains("//", StringComparison.Ordinal)
        && !package.EndsWith('/')
        && package.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-' or '@' or '/' or '~');

    /// <summary>
    /// The member path of a JavaScript symbol: <c>*</c> (any use of the package), or identifiers separated by dots (ASCII letters,
    /// digits, <c>_</c> and <c>$</c>, not starting with a digit), the last of which may be <c>*</c> (any member, and constructing
    /// the type): <c>template</c>, <c>Parser.parse</c>, <c>Parser.*</c>, <c>default</c>.
    /// </summary>
    public static bool IsValidJsPath(string? path)
    {
        if (string.IsNullOrEmpty(path) || path.Length > MaxLength)
        {
            return false;
        }

        if (path == "*")
        {
            return true;
        }

        string[] parts = path.Split('.');
        string[] identifiers = parts[^1] == "*" ? parts[..^1] : parts;

        return identifiers.Length > 0 && identifiers.All(IsJsIdentifier);
    }

    /// <summary>
    /// The full symbol the analyzer is asked about for an entry of a symbol map. <paramref name="symbol"/> is either a path relative
    /// to the entry's package (<c>Parser.parse</c>) or a full <c>specifier::path</c> whose specifier is the package or a subpath of
    /// it (<c>lodash/fp::map</c>): an entry cannot name symbols of another package. Null if it is neither.
    /// </summary>
    public static string? ComposeJs(string package, string? symbol)
    {
        if (!IsValidJsPackage(package) || string.IsNullOrEmpty(symbol))
        {
            return null;
        }

        int split = symbol.IndexOf("::", StringComparison.Ordinal);

        if (split < 0)
        {
            return IsValidJsPath(symbol) ? $"{package}::{symbol}" : null;
        }

        string specifier = symbol[..split];
        bool within = specifier.Equals(package, StringComparison.Ordinal) || specifier.StartsWith(package + "/", StringComparison.Ordinal);

        return within && IsValidJsPackage(specifier) && IsValidJsPath(symbol[(split + 2)..]) && symbol.Length <= MaxLength ? symbol : null;
    }

    /// <summary>A JavaScript function id as the analyzer reports it: <c>path/to/file.js::name</c>, <c>path/to/file.ts::Class.method</c>, or <c>path/to/file.js::*</c>.</summary>
    public static bool IsValidJsFunctionId(string? id)
    {
        if (string.IsNullOrEmpty(id) || id.Length > MaxLength || id.Any(char.IsControl))
        {
            return false;
        }

        int split = id.IndexOf("::", StringComparison.Ordinal);

        return split > 0 && split < id.Length - 2;
    }

    private static bool IsJsIdentifier(string part) =>
        part.Length > 0
        && (char.IsAsciiLetter(part[0]) || part[0] is '_' or '$')
        && part.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '$');
}
