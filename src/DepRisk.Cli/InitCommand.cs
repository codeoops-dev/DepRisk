using DepRisk.Audit;
using DepRisk.Core;

namespace DepRisk.Cli;

/// <summary>
/// <c>deprisk init [path]</c>: creates <c>.deprisk/</c> with a fresh signing key and the first audit entry.
/// Never overwrites anything. Running it again is harmless.
/// </summary>
internal static class InitCommand
{
    public static ExitCode Run(string[] args, TextWriter output, CliContext context)
    {
        string? path = null;

        foreach (string arg in args)
        {
            if (arg.StartsWith('-'))
            {
                throw new InvalidInputException($"unknown option '{arg}' for 'init'.");
            }

            if (path is not null)
            {
                throw new InvalidInputException("'init' takes at most one path.");
            }

            path = arg;
        }

        string target = Path.GetFullPath(path ?? ".", context.WorkingDirectory);

        if (!Directory.Exists(target))
        {
            throw new InvalidInputException($"directory not found: {path}");
        }

        if (AuditStore.IsInitialized(target))
        {
            output.Write($"Already initialized: {Path.Combine(target, AuditStore.DirectoryName)}\nNothing was changed.\n");
            return ExitCode.Success;
        }

        AuditStore store = AuditStore.Initialize(target, out AuditSigner signer);

        using (signer)
        {
            AuditDraft draft = new(
                "init",
                ArgRedactor.Redact(args),
                Digest.Sha256Hex(string.Empty),
                Digest.Sha256Hex(signer.ExportPublicPem()),
                [
                    new AuditChange($"{AuditStore.DirectoryName}/{AuditStore.PrivateKeyFileName}", null, "created"),
                    new AuditChange($"{AuditStore.DirectoryName}/{AuditStore.PublicKeyFileName}", null, "created"),
                    new AuditChange($"{AuditStore.DirectoryName}/.gitignore", null, "created"),
                ]);

            AuditEnvironment environment = new(
                context.Clock(),
                context.Actor,
                context.Host,
                context.WorkingDirectory,
                GitHead.TryReadCommit(target));

            new AuditLog(store).Append(draft, environment, signer);
        }

        output.Write($"Initialized the DepRisk audit store in {store.Directory}\n");
        output.Write($"  {AuditStore.PrivateKeyFileName,-10} private signing key. Keep it secret; it is excluded from Git.\n");
        output.Write($"  {AuditStore.PublicKeyFileName,-10} public key. Share it with anyone who needs to verify the log.\n");
        output.Write($"  {AuditStore.LogFileName,-10} hash-chained, signed log (first entry written).\n");
        output.Write("\nFrom now on, commands run in this project record what they did. Verify at any time with:\n");
        output.Write("  deprisk audit verify\n");
        return ExitCode.Success;
    }
}
