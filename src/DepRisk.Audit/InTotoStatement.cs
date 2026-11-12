using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace DepRisk.Audit;

/// <summary>An artifact a statement is about: a name and the SHA-256 of its content (64 lowercase hexadecimal digits).</summary>
public sealed record AttestationSubject(string Name, string Sha256);

/// <summary>A parsed in-toto statement: who it is about, what kind of predicate it carries, and the predicate as JSON text.</summary>
public sealed record StatementInfo(IReadOnlyList<AttestationSubject> Subjects, string PredicateType, string PredicateJson);

/// <summary>
/// An in-toto Statement v1 (https://github.com/in-toto/attestation): the layer between DSSE and the document that is attested. For
/// OpenVEX the predicate type is <c>https://openvex.dev/ns/v0.2.0</c> and the predicate is the OpenVEX document (ADR 0021).
/// </summary>
public static class InTotoStatement
{
    public const string StatementType = "https://in-toto.io/Statement/v1";
    public const string PayloadType = "application/vnd.in-toto+json";
    public const int MaxSubjects = 100;

    public static byte[] Create(IReadOnlyList<AttestationSubject> subjects, string predicateType, string predicateJson)
    {
        ArgumentNullException.ThrowIfNull(subjects);
        ArgumentNullException.ThrowIfNull(predicateType);
        ArgumentNullException.ThrowIfNull(predicateJson);

        if (subjects.Count is 0 or > MaxSubjects)
        {
            throw new AuditException($"a statement needs 1 to {MaxSubjects} subjects.");
        }

        JsonArray subjectArray = [];

        foreach (AttestationSubject s in subjects)
        {
            if (!IsDigest(s.Sha256) || string.IsNullOrWhiteSpace(s.Name) || s.Name.Length > 500 || s.Name.Any(char.IsControl))
            {
                throw new AuditException("a subject needs a name (up to 500 characters, no control characters) and a SHA-256 digest of 64 hexadecimal digits.");
            }

            subjectArray.Add(new JsonObject { ["name"] = s.Name, ["digest"] = new JsonObject { ["sha256"] = s.Sha256 } });
        }

        JsonNode predicate = JsonNode.Parse(predicateJson) ?? throw new AuditException("the predicate is empty.");

        JsonObject statement = new()
        {
            ["_type"] = StatementType,
            ["subject"] = subjectArray,
            ["predicateType"] = predicateType,
            ["predicate"] = predicate,
        };

        return Encoding.UTF8.GetBytes(statement.ToJsonString(new JsonSerializerOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));
    }

    /// <exception cref="AuditException">The payload is not an in-toto Statement v1 with at least one subject that carries a SHA-256 digest.</exception>
    public static StatementInfo Parse(byte[] payload)
    {
        ArgumentNullException.ThrowIfNull(payload);

        JsonDocument document;

        try
        {
            document = JsonDocument.Parse(payload, new JsonDocumentOptions { MaxDepth = 64 });
        }
        catch (JsonException ex)
        {
            throw new AuditException($"the payload is not valid JSON ({ex.Message})", ex);
        }

        using (document)
        {
            JsonElement root = document.RootElement;

            if (root.ValueKind != JsonValueKind.Object || Text(root, "_type") != StatementType)
            {
                throw new AuditException($"the payload is not an in-toto statement of type {StatementType}.");
            }

            if (!root.TryGetProperty("subject", out JsonElement subjects) || subjects.ValueKind != JsonValueKind.Array || subjects.GetArrayLength() is 0 or > MaxSubjects)
            {
                throw new AuditException($"a statement needs 1 to {MaxSubjects} subjects.");
            }

            List<AttestationSubject> list = [];

            foreach (JsonElement s in subjects.EnumerateArray())
            {
                string? name = s.ValueKind == JsonValueKind.Object ? Text(s, "name") : null;
                string? digest = s.ValueKind == JsonValueKind.Object && s.TryGetProperty("digest", out JsonElement d) && d.ValueKind == JsonValueKind.Object ? Text(d, "sha256") : null;

                if (name is null || digest is null || !IsDigest(digest))
                {
                    throw new AuditException("every subject needs a name and a sha256 digest.");
                }

                list.Add(new AttestationSubject(name, digest));
            }

            string predicateType = Text(root, "predicateType") ?? throw new AuditException("the statement has no predicateType.");

            if (!root.TryGetProperty("predicate", out JsonElement predicate) || predicate.ValueKind != JsonValueKind.Object)
            {
                throw new AuditException("the statement has no predicate.");
            }

            return new StatementInfo(list, predicateType, predicate.GetRawText());
        }
    }

    public static bool IsDigest(string? hex) => hex is { Length: 64 } && hex.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static string? Text(JsonElement element, string name) =>
        element.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}
