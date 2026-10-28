namespace DepRisk.Audit;

/// <summary>One thing a command changed: <c>subject</c> went from <c>From</c> to <c>To</c> (null means "did not exist").</summary>
public sealed record AuditChange(string Subject, string? From, string? To);

/// <summary>What a command wants recorded. The log adds sequence number, chain hash, and signature.</summary>
public sealed record AuditDraft(
    string Command,
    IReadOnlyList<string> Args,
    string InputsDigest,
    string OutputsDigest,
    IReadOnlyList<AuditChange> Changes);

/// <summary>Who ran the command, where, and when. Supplied by the caller so the log never reads global state itself.</summary>
public sealed record AuditEnvironment(
    DateTimeOffset Timestamp,
    string Actor,
    string Host,
    string WorkingDirectory,
    string? GitCommit);

/// <summary>
/// One line of <c>audit.log</c>. Public contract: schemas/audit-entry.v1.schema.json, docs/audit-log.md.
/// </summary>
public sealed record AuditEntry(
    int Seq,
    string Timestamp,
    string Actor,
    string Host,
    string Cwd,
    string? GitCommit,
    string Command,
    IReadOnlyList<string> Args,
    string InputsDigest,
    string OutputsDigest,
    IReadOnlyList<AuditChange> Changes,
    string PrevHash,
    string Signature)
{
    public const int CurrentSchemaVersion = 1;
}

/// <summary>Result of verifying a whole log.</summary>
public sealed record AuditVerification(bool Ok, int Entries, string Head, string? Error, int FailedLine)
{
    public static AuditVerification Failure(int line, string error, int entries, string head) =>
        new(false, entries, head, error, line);
}
