using DepRisk.Audit;
using DepRisk.Core;

namespace DepRisk.Cli;

/// <summary>
/// <c>deprisk audit verify [path] [--pubkey file] [--head hash]</c>: checks the whole audit log.
/// Verification only reads; it never adds an entry (that would change the head it is checking).
/// </summary>
internal static class AuditCommand
{
    public static ExitCode Run(string[] args, TextWriter output, TextWriter error, CliContext context)
    {
        if (args.Length == 0 || args[0] != "verify")
        {
            throw new InvalidInputException(
                args.Length == 0
                    ? "'audit' needs a subcommand. Available: verify."
                    : $"unknown audit subcommand '{args[0]}'. Available: verify.");
        }

        string? path = null;
        string? publicKeyPath = null;
        string? expectedHead = null;

        for (int i = 1; i < args.Length; i++)
        {
            string arg = args[i];

            if (arg == "--pubkey")
            {
                publicKeyPath = ReadValue(args, ref i, arg);
            }
            else if (arg.StartsWith("--pubkey=", StringComparison.Ordinal))
            {
                publicKeyPath = arg["--pubkey=".Length..];
            }
            else if (arg == "--head")
            {
                expectedHead = ReadValue(args, ref i, arg);
            }
            else if (arg.StartsWith("--head=", StringComparison.Ordinal))
            {
                expectedHead = arg["--head=".Length..];
            }
            else if (arg.StartsWith('-'))
            {
                throw new InvalidInputException($"unknown option '{arg}' for 'audit verify'.");
            }
            else if (path is null)
            {
                path = arg;
            }
            else
            {
                throw new InvalidInputException("'audit verify' takes at most one path.");
            }
        }

        if (expectedHead is not null && !Digest.IsSha256Hex(expectedHead))
        {
            throw new InvalidInputException("'--head' must be 64 lowercase hexadecimal characters.");
        }

        string start = Path.GetFullPath(path ?? ".", context.WorkingDirectory);
        AuditStore store = AuditStore.Find(start)
            ?? throw new InvalidInputException($"no audit store found at or above '{start}'. Run 'deprisk init' first.");

        string keyPath = publicKeyPath is null ? store.PublicKeyPath : Path.GetFullPath(publicKeyPath, context.WorkingDirectory);

        using AuditSigner verifier = AuditSigner.LoadPublic(keyPath);
        AuditVerification result = AuditLog.Verify(store.LogPath, verifier, expectedHead);

        if (!result.Ok)
        {
            string where = result.FailedLine > 0 ? $" at line {result.FailedLine}" : string.Empty;
            error.Write($"{ProductInfo.CommandName}: audit verification FAILED{where}: {result.Error}\n");
            return ExitCode.AuditIntegrityFailure;
        }

        output.Write($"Audit log OK: {result.Entries} entr{(result.Entries == 1 ? "y" : "ies")}\n");
        output.Write($"head: {result.Head}\n");
        return ExitCode.Success;
    }

    private static string ReadValue(string[] args, ref int index, string option)
    {
        if (index + 1 >= args.Length)
        {
            throw new InvalidInputException($"option '{option}' needs a value.");
        }

        index++;
        return args[index];
    }
}
