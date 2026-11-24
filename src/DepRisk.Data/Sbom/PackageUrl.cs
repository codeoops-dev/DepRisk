namespace DepRisk.Data.Sbom;

/// <summary>
/// The parts of a Package URL (<c>pkg:type/namespace/name@version?qualifiers#subpath</c>) that DepRisk uses. Qualifiers and the
/// subpath are dropped, never copied: they can carry a repository or download URL, and so a credential (ADR 0027).
/// </summary>
internal sealed record PackageUrl(string Type, string? Namespace, string Name, string? Version)
{
    /// <summary>
    /// Parses a purl. Returns false for text that is not a purl or has no type or no name. The scheme and the type are not case
    /// sensitive; each segment is percent-decoded, so <c>pkg:npm/%40scope/name@1.0.0</c> and <c>pkg:npm/@scope/name@1.0.0</c> are the same.
    /// </summary>
    public static bool TryParse(string? text, out PackageUrl? purl)
    {
        purl = null;

        if (string.IsNullOrWhiteSpace(text) || !text.StartsWith("pkg:", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string rest = text[4..].Trim().TrimStart('/');

        int hash = rest.IndexOf('#', StringComparison.Ordinal);

        if (hash >= 0)
        {
            rest = rest[..hash];
        }

        int query = rest.IndexOf('?', StringComparison.Ordinal);

        if (query >= 0)
        {
            rest = rest[..query];
        }

        int firstSlash = rest.IndexOf('/', StringComparison.Ordinal);

        if (firstSlash <= 0)
        {
            return false;
        }

        string type = rest[..firstSlash].ToLowerInvariant();
        string path = rest[(firstSlash + 1)..];

        // The version follows the last '@'. A scope written with a raw '@' (@scope/name) starts the path and is not a version.
        string? version = null;
        int at = path.LastIndexOf('@');

        if (at > 0)
        {
            version = Decode(path[(at + 1)..]);
            path = path[..at];
        }

        string[] segments = path.Split('/').Select(Decode).ToArray();

        if (segments.Length == 0 || segments.Any(s => s.Length == 0))
        {
            return false;
        }

        purl = new PackageUrl(
            type,
            segments.Length > 1 ? string.Join('/', segments[..^1]) : null,
            segments[^1],
            string.IsNullOrEmpty(version) ? null : version);

        return true;
    }

    private static string Decode(string segment) => Uri.UnescapeDataString(segment);
}
