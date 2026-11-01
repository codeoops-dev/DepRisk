using System.Text;

namespace DepRisk.Core.Versioning;

/// <summary>
/// A NuGet version range: a lower and/or upper bound, each inclusive or exclusive.
/// Understood forms:
/// <list type="bullet">
/// <item>a plain version <c>1.2.3</c>: that version or higher (minimum, inclusive);</item>
/// <item>interval notation: <c>[1.0,2.0)</c>, <c>(1.0,)</c>, <c>(,1.0]</c>, <c>[1.0]</c> (exactly);</item>
/// <item>comparators as written in <c>project.assets.json</c> dependency groups: <c>&gt;= 1.0</c>, <c>&gt; 1.0</c>,
/// <c>&lt;= 2.0</c>, <c>&lt; 2.0</c>, <c>= 1.0</c>, and combinations such as <c>&gt;= 1.0 &lt; 2.0</c> (optionally with
/// <c>&amp;&amp;</c> and surrounding parentheses).</item>
/// </list>
/// Floating versions (<c>1.*</c>) and anything else are not understood: <see cref="TryParse"/> returns false rather than guessing.
/// </summary>
public sealed class NuGetVersionRange
{
    private NuGetVersionRange(NuGetVersion? min, bool minInclusive, NuGetVersion? max, bool maxInclusive)
    {
        Min = min;
        MinInclusive = minInclusive;
        Max = max;
        MaxInclusive = maxInclusive;
    }

    public NuGetVersion? Min { get; }

    public bool MinInclusive { get; }

    public NuGetVersion? Max { get; }

    public bool MaxInclusive { get; }

    public static bool TryParse(string? text, out NuGetVersionRange? range)
    {
        range = null;

        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        string trimmed = text.Trim();

        // "(>= 1.0.0 && < 2.0.0)": comparators in parentheses, not an interval.
        if (trimmed.Length > 2 && trimmed[0] == '(' && trimmed[^1] == ')' && trimmed[1..^1].TrimStart() is [('>' or '<' or '='), ..])
        {
            return TryParseComparators(trimmed[1..^1], out range);
        }

        if (trimmed[0] is '[' or '(')
        {
            return TryParseInterval(trimmed, out range);
        }

        if (NuGetVersion.TryParse(trimmed, out NuGetVersion? plain) && plain is not null)
        {
            range = new NuGetVersionRange(plain, true, null, false);
            return true;
        }

        return TryParseComparators(trimmed, out range);
    }

    public bool Contains(NuGetVersion version)
    {
        ArgumentNullException.ThrowIfNull(version);

        if (Min is not null)
        {
            int byMin = version.CompareTo(Min);

            if (MinInclusive ? byMin < 0 : byMin <= 0)
            {
                return false;
            }
        }

        if (Max is not null)
        {
            int byMax = version.CompareTo(Max);

            if (MaxInclusive ? byMax > 0 : byMax >= 0)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Normalized interval notation, for example <c>[1.0.0, 2.0.0)</c>, <c>[1.0.0, )</c>, or <c>[1.0.0]</c>.</summary>
    public override string ToString()
    {
        if (Min is not null && Max is not null && Min.Equals(Max) && MinInclusive && MaxInclusive)
        {
            return $"[{Min}]";
        }

        StringBuilder text = new();
        text.Append(Min is null || !MinInclusive ? '(' : '[');
        text.Append(Min?.ToString() ?? string.Empty);
        text.Append(", ");
        text.Append(Max?.ToString() ?? string.Empty);
        text.Append(Max is not null && MaxInclusive ? ']' : ')');
        return text.ToString();
    }

    private static bool TryParseInterval(string text, out NuGetVersionRange? range)
    {
        range = null;

        if (text.Length < 3)
        {
            return false;
        }

        bool minInclusive = text[0] == '[';
        char close = text[^1];

        if (close is not (']' or ')'))
        {
            return false;
        }

        bool maxInclusive = close == ']';
        string inner = text[1..^1];
        int comma = inner.IndexOf(',', StringComparison.Ordinal);

        if (comma < 0)
        {
            // "[1.0]" means exactly 1.0; "(1.0)", "[1.0)" and "(1.0]" are invalid.
            if (!(minInclusive && maxInclusive) || !NuGetVersion.TryParse(inner.Trim(), out NuGetVersion? exact) || exact is null)
            {
                return false;
            }

            range = new NuGetVersionRange(exact, true, exact, true);
            return true;
        }

        if (inner.IndexOf(',', comma + 1) >= 0)
        {
            return false;
        }

        string minText = inner[..comma].Trim();
        string maxText = inner[(comma + 1)..].Trim();

        if (minText.Length == 0 && maxText.Length == 0)
        {
            return false;
        }

        NuGetVersion? min = null;
        NuGetVersion? max = null;

        if (minText.Length > 0 && !NuGetVersion.TryParse(minText, out min))
        {
            return false;
        }

        if (maxText.Length > 0 && !NuGetVersion.TryParse(maxText, out max))
        {
            return false;
        }

        return Create(min, minInclusive, max, maxInclusive, out range);
    }

    private static bool TryParseComparators(string text, out NuGetVersionRange? range)
    {
        range = null;
        string cleaned = text.Trim();

        if (cleaned.StartsWith('(') && cleaned.EndsWith(')'))
        {
            cleaned = cleaned[1..^1];
        }

        List<string> tokens = Tokenize(cleaned);

        NuGetVersion? min = null;
        bool minInclusive = false;
        NuGetVersion? max = null;
        bool maxInclusive = false;
        bool hasMin = false;
        bool hasMax = false;
        int index = 0;

        while (index < tokens.Count)
        {
            string token = tokens[index];

            if (token == "&&")
            {
                index++;
                continue;
            }

            if (token is not (">=" or ">" or "<=" or "<" or "=") || index + 1 >= tokens.Count
                || !NuGetVersion.TryParse(tokens[index + 1], out NuGetVersion? version) || version is null)
            {
                return false;
            }

            switch (token)
            {
                case ">=" or ">":
                    if (hasMin)
                    {
                        return false;
                    }

                    (min, minInclusive, hasMin) = (version, token == ">=", true);
                    break;
                case "<=" or "<":
                    if (hasMax)
                    {
                        return false;
                    }

                    (max, maxInclusive, hasMax) = (version, token == "<=", true);
                    break;
                default:
                    if (hasMin || hasMax)
                    {
                        return false;
                    }

                    (min, minInclusive, hasMin) = (version, true, true);
                    (max, maxInclusive, hasMax) = (version, true, true);
                    break;
            }

            index += 2;
        }

        return hasMin || hasMax ? Create(min, minInclusive, max, maxInclusive, out range) : false;
    }

    /// <summary>Splits "&gt;= 1.0 &lt; 2.0" and "&gt;=1.0&lt;2.0" into operators and versions.</summary>
    private static List<string> Tokenize(string text)
    {
        List<string> tokens = [];
        StringBuilder current = new();

        void Flush()
        {
            if (current.Length > 0)
            {
                tokens.Add(current.ToString());
                current.Clear();
            }
        }

        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];

            if (char.IsWhiteSpace(c))
            {
                Flush();
            }
            else if (c is '>' or '<' or '=')
            {
                Flush();
                current.Append(c);

                if (i + 1 < text.Length && text[i + 1] == '=' && c != '=')
                {
                    current.Append('=');
                    i++;
                }

                Flush();
            }
            else if (c == '&' && i + 1 < text.Length && text[i + 1] == '&')
            {
                Flush();
                tokens.Add("&&");
                i++;
            }
            else
            {
                current.Append(c);
            }
        }

        Flush();
        return tokens;
    }

    private static bool Create(NuGetVersion? min, bool minInclusive, NuGetVersion? max, bool maxInclusive, out NuGetVersionRange? range)
    {
        range = null;

        if (min is not null && max is not null)
        {
            int order = min.CompareTo(max);

            // An empty range (min above max, or equal bounds that are not both inclusive) is a mistake, not a range.
            if (order > 0 || (order == 0 && !(minInclusive && maxInclusive)))
            {
                return false;
            }
        }

        range = new NuGetVersionRange(min, minInclusive, max, maxInclusive);
        return true;
    }
}
