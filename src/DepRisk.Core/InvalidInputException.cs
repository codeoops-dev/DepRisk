namespace DepRisk.Core;

/// <summary>
/// The user supplied something we cannot work with (bad path, unreadable or unsupported file, bad option).
/// The CLI reports the message and exits with <see cref="ExitCode.InvalidInput"/>.
/// </summary>
public sealed class InvalidInputException : Exception
{
    public InvalidInputException(string message)
        : base(message)
    {
    }

    public InvalidInputException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
