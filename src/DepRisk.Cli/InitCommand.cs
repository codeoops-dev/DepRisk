using DepRisk.Audit;
using DepRisk.Core;

namespace DepRisk.Cli;

/// <summary>
/// <c>deprisk init [path] [--key-file file] [--encrypt]</c>: creates <c>.deprisk/</c> with a fresh signing key and the first audit entry.
/// <c>--key-file</c> puts the private key somewhere else (name it later in <c>DEPRISK_KEY_FILE</c>); <c>--encrypt</c> encrypts it with
/// the passphrase in <c>DEPRISK_KEY_PASSPHRASE</c> or in the file named by <c>DEPRISK_KEY_PASSPHRASE_FILE</c> (never given on the command
/// line). Never overwrites anything. Running it again is harmless. See ADR 0030.
/// </summary>
internal static class InitCommand
{
    public static ExitCode Run(string[] args, TextWriter output, CliContext context)
    {
        string? path = null;
        string? keyFile = null;
        bool encrypt = false;

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];

            if (OptionValue.TryValue(args, ref i, arg, "--key-file", null, out string? value))
            {
                keyFile = value;
            }
            else if (arg == "--encrypt")
            {
                encrypt = true;
            }
            else if (arg.StartsWith('-'))
            {
                throw new InvalidInputException($"unknown option '{arg}' for 'init'.");
            }
            else if (path is not null)
            {
                throw new InvalidInputException("'init' takes at most one path.");
            }
            else
            {
                path = arg;
            }
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

        string? passphrase = null;

        if (encrypt)
        {
            try
            {
                passphrase = KeyPassphrase.Read(context.GetEnvironmentVariable, context.WorkingDirectory);
            }
            catch (AuditException ex)
            {
                throw new InvalidInputException(ex.Message, ex);
            }

            if (passphrase is null)
            {
                throw new InvalidInputException(
                    $"--encrypt needs a passphrase: set {KeyPassphrase.EnvironmentVariable}, or {KeyPassphrase.FileEnvironmentVariable} to the path of a file that holds it. "
                    + "It is not taken from the command line, where it would show in the process list and the shell history.");
            }
        }

        AuditStore store;
        AuditSigner signer;

        try
        {
            store = AuditStore.Initialize(target, out signer, keyFile is null ? null : Path.GetFullPath(keyFile, context.WorkingDirectory), passphrase);
        }
        catch (AuditException ex) when (keyFile is not null || passphrase is not null)
        {
            throw new InvalidInputException(ex.Message, ex);
        }

        string keyState = passphrase is null ? "created" : "created, encrypted with a passphrase";
        string keySubject = keyFile is null ? $"{AuditStore.DirectoryName}/{AuditStore.PrivateKeyFileName}" : "private key file outside .deprisk";

        using (signer)
        {
            AuditDraft draft = new(
                "init",
                ArgRedactor.Redact(args),
                Digest.Sha256Hex(string.Empty),
                Digest.Sha256Hex(signer.ExportPublicPem()),
                [
                    new AuditChange(keySubject, null, keyState),
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

        if (keyFile is null)
        {
            output.Write($"  {AuditStore.PrivateKeyFileName,-10} private signing key{(passphrase is null ? string.Empty : ", encrypted with your passphrase")}. Keep it secret; it is excluded from Git.\n");
        }
        else
        {
            string fullKeyFile = Path.GetFullPath(keyFile, context.WorkingDirectory);
            output.Write($"  private signing key{(passphrase is null ? string.Empty : " (encrypted with your passphrase)")}: {fullKeyFile}\n");
            output.Write($"  Commands that write the audit log find it through the variable {AuditStore.KeyFileEnvironmentVariable}: set it to that path.\n");
        }

        output.Write($"  {AuditStore.PublicKeyFileName,-10} public key. Share it with anyone who needs to verify the log.\n");
        output.Write($"  {AuditStore.LogFileName,-10} hash-chained, signed log (first entry written).\n");
        output.Write("\nFrom now on, commands run in this project record what they did. Verify at any time with:\n");
        output.Write("  deprisk audit verify\n");
        return ExitCode.Success;
    }
}
