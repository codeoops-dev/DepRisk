namespace DepRisk.Data.Reach;

/// <summary>The analyzer could not be run, failed, or returned something that does not follow the protocol (an internal error, exit 5).</summary>
public sealed class AnalyzerException : Exception
{
    public AnalyzerException(string message)
        : base(message)
    {
    }

    public AnalyzerException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
