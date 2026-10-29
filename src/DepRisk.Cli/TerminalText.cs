using System.Text;

namespace DepRisk.Cli;

/// <summary>
/// Makes text from untrusted data (advisory summaries, package names) safe to print: control characters, including the
/// escape character that starts terminal control sequences, are replaced, and the length is bounded.
/// </summary>
internal static class TerminalText
{
    public static string Safe(string? text, int maxLength)
    {
        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        StringBuilder builder = new(Math.Min(text.Length, maxLength + 1));

        foreach (char c in text)
        {
            if (builder.Length >= maxLength)
            {
                builder.Append('…');
                break;
            }

            // C0 controls (including ESC), DEL, C1 controls, and line/paragraph separators.
            builder.Append(c < 0x20 || c is >= '\u007F' and <= '\u009F' || c is '\u2028' or '\u2029' ? ' ' : c);
        }

        return builder.ToString();
    }
}
