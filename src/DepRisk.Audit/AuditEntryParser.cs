using System.Globalization;
using System.Text.Json;
using DepRisk.Core;

namespace DepRisk.Audit;

/// <summary>Strict reader for one log line. Unknown properties, wrong types, and malformed values are errors.</summary>
internal static class AuditEntryParser
{
    internal const string TimestampFormat = "yyyy-MM-dd'T'HH:mm:ss.fff'Z'";

    private static readonly HashSet<string> EntryKeys = new(StringComparer.Ordinal)
    {
        "actor", "args", "changes", "command", "cwd", "gitCommit", "host", "inputsDigest", "outputsDigest",
        "prevHash", "schemaVersion", "seq", "signature", "timestamp",
    };

    public static bool TryParse(string json, out AuditEntry? entry, out string error)
    {
        entry = null;
        error = string.Empty;

        JsonDocument document;

        try
        {
            document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 16 });
        }
        catch (JsonException)
        {
            error = "not valid JSON";
            return false;
        }

        using (document)
        {
            JsonElement root = document.RootElement;

            if (root.ValueKind != JsonValueKind.Object)
            {
                error = "not a JSON object";
                return false;
            }

            HashSet<string> seen = new(StringComparer.Ordinal);

            foreach (JsonProperty property in root.EnumerateObject())
            {
                if (!EntryKeys.Contains(property.Name))
                {
                    error = $"unexpected property '{property.Name}'";
                    return false;
                }

                if (!seen.Add(property.Name))
                {
                    error = $"duplicate property '{property.Name}'";
                    return false;
                }
            }

            if (seen.Count != EntryKeys.Count)
            {
                string missing = string.Join(", ", EntryKeys.Except(seen).Order(StringComparer.Ordinal));
                error = $"missing properties: {missing}";
                return false;
            }

            if (!TryInt(root, "schemaVersion", out int schemaVersion) || schemaVersion != AuditEntry.CurrentSchemaVersion)
            {
                error = $"unsupported schemaVersion (supported: {AuditEntry.CurrentSchemaVersion})";
                return false;
            }

            if (!TryInt(root, "seq", out int seq) || seq < 1)
            {
                error = "'seq' must be an integer >= 1";
                return false;
            }

            if (!TryString(root, "timestamp", out string? timestamp)
                || !DateTimeOffset.TryParseExact(timestamp, TimestampFormat, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out _))
            {
                error = $"'timestamp' must match {TimestampFormat}";
                return false;
            }

            if (!TryString(root, "actor", out string? actor)
                || !TryString(root, "host", out string? host)
                || !TryString(root, "cwd", out string? cwd)
                || !TryString(root, "command", out string? command))
            {
                error = "'actor', 'host', 'cwd', and 'command' must be strings";
                return false;
            }

            string? gitCommit = null;
            JsonElement gitElement = root.GetProperty("gitCommit");

            if (gitElement.ValueKind == JsonValueKind.String)
            {
                gitCommit = gitElement.GetString();
            }
            else if (gitElement.ValueKind != JsonValueKind.Null)
            {
                error = "'gitCommit' must be a string or null";
                return false;
            }

            if (!TryString(root, "inputsDigest", out string? inputs) || !Digest.IsSha256Hex(inputs)
                || !TryString(root, "outputsDigest", out string? outputs) || !Digest.IsSha256Hex(outputs)
                || !TryString(root, "prevHash", out string? prev) || !Digest.IsSha256Hex(prev))
            {
                error = "'inputsDigest', 'outputsDigest', and 'prevHash' must be 64 lowercase hex characters";
                return false;
            }

            if (!TryString(root, "signature", out string? signature))
            {
                error = "'signature' must be a string";
                return false;
            }

            if (!TryStringArray(root.GetProperty("args"), out List<string>? args))
            {
                error = "'args' must be an array of strings";
                return false;
            }

            if (!TryChanges(root.GetProperty("changes"), out List<AuditChange>? changes))
            {
                error = "'changes' must be an array of {subject, from, to}";
                return false;
            }

            entry = new AuditEntry(
                seq, timestamp!, actor!, host!, cwd!, gitCommit, command!, args!, inputs!, outputs!, changes!, prev!, signature!);
            return true;
        }
    }

    private static bool TryInt(JsonElement root, string name, out int value)
    {
        value = 0;
        JsonElement element = root.GetProperty(name);
        return element.ValueKind == JsonValueKind.Number && element.TryGetInt32(out value);
    }

    private static bool TryString(JsonElement root, string name, out string? value)
    {
        JsonElement element = root.GetProperty(name);

        if (element.ValueKind == JsonValueKind.String)
        {
            value = element.GetString();
            return value is not null;
        }

        value = null;
        return false;
    }

    private static bool TryStringArray(JsonElement element, out List<string>? values)
    {
        values = null;

        if (element.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        List<string> result = [];

        foreach (JsonElement item in element.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String || item.GetString() is not { } text)
            {
                return false;
            }

            result.Add(text);
        }

        values = result;
        return true;
    }

    private static bool TryChanges(JsonElement element, out List<AuditChange>? changes)
    {
        changes = null;

        if (element.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        List<AuditChange> result = [];

        foreach (JsonElement item in element.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object
                || !item.TryGetProperty("subject", out JsonElement subject) || subject.ValueKind != JsonValueKind.String
                || !item.TryGetProperty("from", out JsonElement from) || !IsStringOrNull(from)
                || !item.TryGetProperty("to", out JsonElement to) || !IsStringOrNull(to)
                || item.EnumerateObject().Count() != 3)
            {
                return false;
            }

            result.Add(new AuditChange(subject.GetString()!, from.GetString(), to.GetString()));
        }

        changes = result;
        return true;
    }

    private static bool IsStringOrNull(JsonElement element) =>
        element.ValueKind is JsonValueKind.String or JsonValueKind.Null;
}
