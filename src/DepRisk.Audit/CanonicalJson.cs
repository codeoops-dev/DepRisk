using System.Globalization;
using System.Text;

namespace DepRisk.Audit;

/// <summary>
/// The canonical serialization of an audit entry, used for hashing, signing, and as the stored line.
/// It follows RFC 8785 (JSON Canonicalization Scheme) for the value types we use: object keys sorted by UTF-16
/// code units, no insignificant whitespace, minimal string escapes, integers only. Anyone can reproduce it
/// in any language; see docs/audit-log.md.
/// </summary>
internal static class CanonicalJson
{
    /// <summary>Every field except "signature": the exact bytes that are signed.</summary>
    public static string Body(AuditEntry entry) => Build(entry, includeSignature: false);

    /// <summary>Every field: the stored line, and the input of the next entry's "prevHash".</summary>
    public static string Full(AuditEntry entry) => Build(entry, includeSignature: true);

    private static string Build(AuditEntry e, bool includeSignature)
    {
        StringBuilder sb = new();
        sb.Append('{');

        // Keys in ordinal order: actor, args, changes, command, cwd, gitCommit, host, inputsDigest, outputsDigest,
        // prevHash, schemaVersion, seq, signature, timestamp.
        Key(sb, "actor");
        AppendString(sb, e.Actor);

        sb.Append(',');
        Key(sb, "args");
        sb.Append('[');
        for (int i = 0; i < e.Args.Count; i++)
        {
            if (i > 0)
            {
                sb.Append(',');
            }

            AppendString(sb, e.Args[i]);
        }

        sb.Append(']');

        sb.Append(',');
        Key(sb, "changes");
        sb.Append('[');
        for (int i = 0; i < e.Changes.Count; i++)
        {
            if (i > 0)
            {
                sb.Append(',');
            }

            AuditChange change = e.Changes[i];
            sb.Append('{');
            Key(sb, "from");
            AppendString(sb, change.From);
            sb.Append(',');
            Key(sb, "subject");
            AppendString(sb, change.Subject);
            sb.Append(',');
            Key(sb, "to");
            AppendString(sb, change.To);
            sb.Append('}');
        }

        sb.Append(']');

        sb.Append(',');
        Key(sb, "command");
        AppendString(sb, e.Command);

        sb.Append(',');
        Key(sb, "cwd");
        AppendString(sb, e.Cwd);

        sb.Append(',');
        Key(sb, "gitCommit");
        AppendString(sb, e.GitCommit);

        sb.Append(',');
        Key(sb, "host");
        AppendString(sb, e.Host);

        sb.Append(',');
        Key(sb, "inputsDigest");
        AppendString(sb, e.InputsDigest);

        sb.Append(',');
        Key(sb, "outputsDigest");
        AppendString(sb, e.OutputsDigest);

        sb.Append(',');
        Key(sb, "prevHash");
        AppendString(sb, e.PrevHash);

        sb.Append(',');
        Key(sb, "schemaVersion");
        sb.Append(AuditEntry.CurrentSchemaVersion.ToString(CultureInfo.InvariantCulture));

        sb.Append(',');
        Key(sb, "seq");
        sb.Append(e.Seq.ToString(CultureInfo.InvariantCulture));

        if (includeSignature)
        {
            sb.Append(',');
            Key(sb, "signature");
            AppendString(sb, e.Signature);
        }

        sb.Append(',');
        Key(sb, "timestamp");
        AppendString(sb, e.Timestamp);

        sb.Append('}');
        return sb.ToString();
    }

    private static void Key(StringBuilder sb, string name)
    {
        AppendString(sb, name);
        sb.Append(':');
    }

    /// <summary>
    /// RFC 8785 string form: only '"', '\', and control characters are escaped. A lone surrogate cannot be
    /// represented in UTF-8 JSON, so it is replaced by U+FFFD before hashing (the same text is then stored and verified).
    /// </summary>
    internal static void AppendString(StringBuilder sb, string? value)
    {
        if (value is null)
        {
            sb.Append("null");
            return;
        }

        sb.Append('"');

        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];

            switch (c)
            {
                case '"':
                    sb.Append("\\\"");
                    break;
                case '\\':
                    sb.Append("\\\\");
                    break;
                case '\b':
                    sb.Append("\\b");
                    break;
                case '\t':
                    sb.Append("\\t");
                    break;
                case '\n':
                    sb.Append("\\n");
                    break;
                case '\f':
                    sb.Append("\\f");
                    break;
                case '\r':
                    sb.Append("\\r");
                    break;
                default:
                    if (c < 0x20)
                    {
                        sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else if (char.IsHighSurrogate(c) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
                    {
                        sb.Append(c).Append(value[i + 1]);
                        i++;
                    }
                    else if (char.IsSurrogate(c))
                    {
                        sb.Append('\uFFFD');
                    }
                    else
                    {
                        sb.Append(c);
                    }

                    break;
            }
        }

        sb.Append('"');
    }
}
