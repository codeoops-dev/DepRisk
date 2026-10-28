using DepRisk.Audit;

namespace DepRisk.Cli;

/// <summary>Writes an audit entry for a command, if the project has been initialized with <c>deprisk init</c>.</summary>
internal static class AuditRecorder
{
    /// <returns>true if an entry was written.</returns>
    public static bool RecordIfEnabled(CliContext context, AuditDraft draft)
    {
        AuditStore? store = AuditStore.Find(context.WorkingDirectory);

        if (store is null)
        {
            return false;
        }

        // From here on the project asked for an audit trail, so a failure must stop the command (exit code 3).
        using AuditSigner signer = store.LoadSigner();

        AuditEnvironment environment = new(
            context.Clock(),
            context.Actor,
            context.Host,
            context.WorkingDirectory,
            GitHead.TryReadCommit(context.WorkingDirectory));

        new AuditLog(store).Append(draft, environment, signer);
        return true;
    }
}
