namespace DepRisk.Core;

/// <summary>
/// Process exit codes. These values are a public contract (documented in the README);
/// do not renumber. Adding a new code requires an ADR.
/// </summary>
public enum ExitCode
{
    /// <summary>Success, policy satisfied.</summary>
    Success = 0,

    /// <summary>Policy gate failed (for example, a reachable finding above the threshold).</summary>
    PolicyGateFailed = 1,

    /// <summary>Plan verification failed.</summary>
    PlanVerificationFailed = 2,

    /// <summary>Audit log integrity failure.</summary>
    AuditIntegrityFailure = 3,

    /// <summary>Input or configuration error (includes unknown commands and bad arguments).</summary>
    InvalidInput = 4,

    /// <summary>Internal error.</summary>
    InternalError = 5,
}
