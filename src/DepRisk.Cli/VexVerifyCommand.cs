using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DepRisk.Audit;
using DepRisk.Core;
using DepRisk.Data.OpenVex;

namespace DepRisk.Cli;

/// <summary>
/// <c>deprisk vex verify &lt;envelope&gt; --pubkey &lt;file&gt; [--subject-file &lt;file&gt;]...</c>: checks a signed OpenVEX document (a DSSE envelope with an
/// in-toto statement, ADR 0021) against a public key, and optionally that it is about the given files. Exit code 3 when something does
/// not verify. A valid signature says who signed, not that the statements are true.
/// </summary>
internal static class VexVerifyCommand
{
    private const long MaxFileBytes = 64L * 1024 * 1024;

    public static ExitCode Run(string[] args, TextWriter output, CliContext context)
    {
        string? envelopePath = null;
        string? pubkey = null;
        List<string> subjectFiles = [];

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];

            if (ReachArgs.TryValue(args, ref i, arg, "--pubkey", null, out string? value))
            {
                pubkey = value;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--subject-file", null, out value))
            {
                subjectFiles.Add(value!);
            }
            else if (arg.StartsWith('-'))
            {
                throw new InvalidInputException($"unknown option '{TerminalText.Safe(arg, 40)}' for 'vex verify'.");
            }
            else if (envelopePath is null)
            {
                envelopePath = arg;
            }
            else
            {
                throw new InvalidInputException("'vex verify' takes one envelope file.");
            }
        }

        if (envelopePath is null)
        {
            throw new InvalidInputException("'vex verify' needs the signed document: deprisk vex verify <envelope.json> --pubkey <public key>.");
        }

        if (pubkey is null)
        {
            throw new InvalidInputException("'vex verify' needs --pubkey <public key file> (an ECDSA P-256 key in PEM form): which key to trust is for you to say.");
        }

        string envelope = ReadText(Path.GetFullPath(envelopePath, context.WorkingDirectory), envelopePath);

        AuditSigner key;

        try
        {
            key = AuditSigner.LoadPublic(Path.GetFullPath(pubkey, context.WorkingDirectory));
        }
        catch (AuditException ex)
        {
            throw new InvalidInputException(ex.Message, ex);
        }

        using (key)
        {
            DsseVerification verified = Dsse.Verify(envelope, key);

            if (verified.PayloadType != InTotoStatement.PayloadType)
            {
                throw new AuditException($"the payload type is '{TerminalText.Safe(verified.PayloadType, 80)}', not an in-toto statement ({InTotoStatement.PayloadType}).");
            }

            StatementInfo statement = InTotoStatement.Parse(verified.Payload);

            if (statement.PredicateType != OpenVexWriter.Context)
            {
                throw new AuditException($"the statement is not about OpenVEX (predicate type '{TerminalText.Safe(statement.PredicateType, 80)}').");
            }

            using JsonDocument predicate = JsonDocument.Parse(statement.PredicateJson);
            JsonElement root = predicate.RootElement;

            if (!root.TryGetProperty("@context", out JsonElement context1) || context1.GetString() != OpenVexWriter.Context
                || !root.TryGetProperty("statements", out JsonElement statements) || statements.ValueKind != JsonValueKind.Array)
            {
                throw new AuditException("the predicate is not an OpenVEX 0.2.0 document.");
            }

            string author = root.TryGetProperty("author", out JsonElement a) && a.ValueKind == JsonValueKind.String ? a.GetString()! : "(none)";
            string id = root.TryGetProperty("@id", out JsonElement idElement) && idElement.ValueKind == JsonValueKind.String ? idElement.GetString()! : "(none)";

            StringBuilder text = new();
            text.Append($"OK: the signature verifies with the public key {key.KeyId()}\n");
            text.Append($"    OpenVEX 0.2.0 by \"{TerminalText.Safe(author, 120)}\": {statements.GetArrayLength()} statement(s), document {TerminalText.Safe(id, 100)}\n");

            foreach (AttestationSubject s in statement.Subjects)
            {
                text.Append($"    about: {TerminalText.Safe(s.Name, 120)} sha256:{s.Sha256}\n");
            }

            foreach (string file in subjectFiles)
            {
                string full = Path.GetFullPath(file, context.WorkingDirectory);
                string digest = Hash(full, file);

                if (!statement.Subjects.Any(s => s.Sha256 == digest))
                {
                    throw new AuditException($"the file '{TerminalText.Safe(file, 80)}' (sha256:{digest}) is not among the subjects of this statement.");
                }

                text.Append($"    the file {TerminalText.Safe(Path.GetFileName(full), 80)} is one of the subjects\n");
            }

            output.Write(text.ToString());
        }

        return ExitCode.Success;
    }

    private static string ReadText(string full, string shown)
    {
        try
        {
            if (new FileInfo(full).Length > MaxFileBytes)
            {
                throw new InvalidInputException($"'{TerminalText.Safe(shown, 80)}' is larger than 64 MB.");
            }

            return File.ReadAllText(full);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InvalidInputException($"cannot read '{TerminalText.Safe(shown, 80)}' ({ex.Message})", ex);
        }
    }

    private static string Hash(string full, string shown)
    {
        try
        {
            using FileStream stream = File.OpenRead(full);
            return Convert.ToHexStringLower(SHA256.HashData(stream));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InvalidInputException($"cannot read the subject file '{TerminalText.Safe(shown, 80)}' ({ex.Message})", ex);
        }
    }
}
