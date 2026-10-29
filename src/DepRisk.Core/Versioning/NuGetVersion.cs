using System.Globalization;

namespace DepRisk.Core.Versioning;

/// <summary>
/// A NuGet package version: <c>Major[.Minor[.Patch[.Revision]]][-prerelease][+metadata]</c>.
/// Ordering follows NuGet's rules (SemVer 2.0 plus an optional fourth numeric part): missing numeric parts are zero,
/// a release is greater than any prerelease of the same numbers, prerelease labels are compared one by one
/// (numeric labels numerically, below alphanumeric labels; alphanumeric labels case-insensitively), a longer
/// label list is greater when all earlier labels are equal, and build metadata is ignored.
/// Implemented here, without a dependency, so the ordering can be reviewed and tested in one place (ADR 0006).
/// </summary>
public sealed class NuGetVersion : IComparable<NuGetVersion>, IEquatable<NuGetVersion>
{
    private NuGetVersion(int major, int minor, int patch, int revision, string[] labels, string? metadata)
    {
        Major = major;
        Minor = minor;
        Patch = patch;
        Revision = revision;
        ReleaseLabels = labels;
        Metadata = metadata;
    }

    public int Major { get; }

    public int Minor { get; }

    public int Patch { get; }

    public int Revision { get; }

    public IReadOnlyList<string> ReleaseLabels { get; }

    public string? Metadata { get; }

    public bool IsPrerelease => ReleaseLabels.Count > 0;

    public static bool TryParse(string? text, out NuGetVersion? version)
    {
        version = null;

        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        string rest = text.Trim();
        string? metadata = null;

        int plus = rest.IndexOf('+', StringComparison.Ordinal);

        if (plus >= 0)
        {
            metadata = rest[(plus + 1)..];

            if (metadata.Length == 0 || !metadata.All(IsMetadataChar))
            {
                return false;
            }

            rest = rest[..plus];
        }

        string[] labels = [];
        int dash = rest.IndexOf('-', StringComparison.Ordinal);

        if (dash >= 0)
        {
            string labelText = rest[(dash + 1)..];
            labels = labelText.Split('.');

            if (labels.Any(l => l.Length == 0 || !l.All(IsLabelChar)))
            {
                return false;
            }

            rest = rest[..dash];
        }

        string[] parts = rest.Split('.');

        if (parts.Length is < 1 or > 4)
        {
            return false;
        }

        int[] numbers = new int[4];

        for (int i = 0; i < parts.Length; i++)
        {
            if (parts[i].Length == 0
                || !int.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out numbers[i]))
            {
                return false;
            }
        }

        version = new NuGetVersion(numbers[0], numbers[1], numbers[2], numbers[3], labels, metadata);
        return true;
    }

    public static NuGetVersion Parse(string text) =>
        TryParse(text, out NuGetVersion? version) && version is not null
            ? version
            : throw new FormatException($"'{text}' is not a valid NuGet version.");

    /// <summary>Normalized form: three numeric parts (four if the revision is not zero), labels, no metadata.</summary>
    public override string ToString()
    {
        string numbers = Revision != 0
            ? $"{Major}.{Minor}.{Patch}.{Revision}"
            : $"{Major}.{Minor}.{Patch}";

        return IsPrerelease ? numbers + "-" + string.Join('.', ReleaseLabels) : numbers;
    }

    public int CompareTo(NuGetVersion? other)
    {
        if (other is null)
        {
            return 1;
        }

        int result = Major.CompareTo(other.Major);

        if (result != 0)
        {
            return result;
        }

        result = Minor.CompareTo(other.Minor);

        if (result != 0)
        {
            return result;
        }

        result = Patch.CompareTo(other.Patch);

        if (result != 0)
        {
            return result;
        }

        result = Revision.CompareTo(other.Revision);

        if (result != 0)
        {
            return result;
        }

        return CompareLabels(ReleaseLabels, other.ReleaseLabels);
    }

    public bool Equals(NuGetVersion? other) => other is not null && CompareTo(other) == 0;

    public override bool Equals(object? obj) => Equals(obj as NuGetVersion);

    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.Add(Major);
        hash.Add(Minor);
        hash.Add(Patch);
        hash.Add(Revision);

        foreach (string label in ReleaseLabels)
        {
            hash.Add(NormalizeNumeric(label), StringComparer.OrdinalIgnoreCase);
        }

        return hash.ToHashCode();
    }

    public static bool operator ==(NuGetVersion? left, NuGetVersion? right) => left is null ? right is null : left.Equals(right);

    public static bool operator !=(NuGetVersion? left, NuGetVersion? right) => !(left == right);

    public static bool operator <(NuGetVersion left, NuGetVersion right) => left.CompareTo(right) < 0;

    public static bool operator >(NuGetVersion left, NuGetVersion right) => left.CompareTo(right) > 0;

    public static bool operator <=(NuGetVersion left, NuGetVersion right) => left.CompareTo(right) <= 0;

    public static bool operator >=(NuGetVersion left, NuGetVersion right) => left.CompareTo(right) >= 0;

    private static int CompareLabels(IReadOnlyList<string> left, IReadOnlyList<string> right)
    {
        // No labels means a release, which is greater than any prerelease.
        if (left.Count == 0)
        {
            return right.Count == 0 ? 0 : 1;
        }

        if (right.Count == 0)
        {
            return -1;
        }

        int shared = Math.Min(left.Count, right.Count);

        for (int i = 0; i < shared; i++)
        {
            int result = CompareLabel(left[i], right[i]);

            if (result != 0)
            {
                return result;
            }
        }

        return left.Count.CompareTo(right.Count);
    }

    private static int CompareLabel(string left, string right)
    {
        bool leftNumeric = left.All(char.IsAsciiDigit);
        bool rightNumeric = right.All(char.IsAsciiDigit);

        if (leftNumeric && rightNumeric)
        {
            // Compare as numbers of any size: strip leading zeros, then longer is greater, then ordinal.
            string a = NormalizeNumeric(left);
            string b = NormalizeNumeric(right);
            int byLength = a.Length.CompareTo(b.Length);
            return byLength != 0 ? byLength : string.CompareOrdinal(a, b);
        }

        if (leftNumeric)
        {
            return -1;
        }

        if (rightNumeric)
        {
            return 1;
        }

        return string.Compare(left, right, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeNumeric(string label)
    {
        if (!label.All(char.IsAsciiDigit))
        {
            return label;
        }

        string trimmed = label.TrimStart('0');
        return trimmed.Length == 0 ? "0" : trimmed;
    }

    private static bool IsLabelChar(char c) => char.IsAsciiLetterOrDigit(c) || c == '-';

    private static bool IsMetadataChar(char c) => char.IsAsciiLetterOrDigit(c) || c is '-' or '.';
}
