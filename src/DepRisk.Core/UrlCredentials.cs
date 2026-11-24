using System.Text;

namespace DepRisk.Core;

/// <summary>
/// Removes credentials from text that came from a dependency file before it can reach an output (a scan result, a graph, a SARIF
/// file, an audit log, a CI artifact). A version range or specifier can be a URL, and a URL can carry credentials
/// (<c>git+https://user:token@host/org/repo.git</c>); the output of DepRisk is meant to be shared, the dependency file is not.
/// See ADR 0027.
/// </summary>
/// <remarks>
/// What is replaced by <see cref="Placeholder"/>: the user information (everything before the last <c>@</c>) of every <c>://</c>
/// authority in the text, and the user part of a scp-like specifier (<c>token@host:org/repo</c>). What is kept: the user
/// <c>git</c> (the public name of <c>git+ssh://git@github.com/...</c>), text that has no <c>@</c>, npm aliases
/// (<c>npm:@scope/name@^1</c>), scoped package names (<c>@scope/name</c>), and everything else as written.
/// The rule errs on the side of masking: an authority ends only at <c>/</c> or <c>\</c>, so anything before an <c>@</c> up to then is
/// treated as user information, whatever characters it holds. The function reads the text once (no regular expression, so no
/// backtracking), does no input or output, and is idempotent. It cannot know a secret that is not user information (a token in a
/// query string or in a path): those stay as written.
/// </remarks>
public static class UrlCredentials
{
    public const string Placeholder = "***";

    private const string PublicUser = "git";

    public static string Mask(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        return text.Contains('@', StringComparison.Ordinal) ? MaskAuthorities(MaskLeadingUser(text)) : text;
    }

    /// <summary>A scp-like specifier has no scheme: <c>user@host:path</c>. The part before the first <c>://</c> is checked for it.</summary>
    private static string MaskLeadingUser(string text)
    {
        if (text.StartsWith("npm:", StringComparison.Ordinal))
        {
            return text;
        }

        int separator = text.IndexOf("://", StringComparison.Ordinal);
        int end = separator < 0 ? text.Length : separator;
        int at = text.IndexOf('@', 0, end);

        // At 0 is a scoped package name (@scope/name), which has no user.
        if (at <= 0)
        {
            return text;
        }

        string user = text[..at];
        return user is PublicUser or Placeholder ? text : Placeholder + text[at..];
    }

    private static string MaskAuthorities(string text)
    {
        StringBuilder? result = null;
        int copied = 0;
        int position = 0;

        while (true)
        {
            int separator = text.IndexOf("://", position, StringComparison.Ordinal);

            if (separator < 0)
            {
                break;
            }

            int start = separator + 3;
            int end = text.IndexOfAny(['/', '\\'], start);

            if (end < 0)
            {
                end = text.Length;
            }

            // The user information is everything before the last '@' of the authority.
            int at = end > start ? text.LastIndexOf('@', end - 1, end - start) : -1;

            if (at >= start)
            {
                string user = text[start..at];

                if (user is not (PublicUser or Placeholder))
                {
                    result ??= new StringBuilder(text.Length);
                    result.Append(text, copied, start - copied).Append(Placeholder);
                    copied = at;
                }
            }

            position = end;
        }

        if (result is null)
        {
            return text;
        }

        result.Append(text, copied, text.Length - copied);
        return result.ToString();
    }
}
