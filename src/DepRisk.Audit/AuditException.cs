namespace DepRisk.Audit;

/// <summary>The audit store is missing something it needs, is damaged, or cannot be written. Maps to exit code 3.</summary>
public sealed class AuditException : Exception
{
    public AuditException(string message)
        : base(message)
    {
    }

    public AuditException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
