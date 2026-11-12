using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using DepRisk.Audit;
using DepRisk.Core;
using DepRisk.Core.Model;
using DepRisk.Data;
using DepRisk.Data.OpenVex;
using DepRisk.Data.Reach;

namespace DepRisk.Cli;

/// <summary>
/// <c>deprisk vex [path] --product &lt;purl|iri&gt; --author &lt;text&gt; [--role text] [--timestamp rfc3339] (analysis options) [--out file]
/// [--sign --key file (--subject-file file | --subject-digest sha256:hex)...]</c> and <c>deprisk vex verify &lt;envelope&gt; --pubkey file</c>:
/// an OpenVEX 0.2.0 document with one statement per finding. <c>not_affected</c> only for findings proven unreachable under the
/// strict conditions (ADR 0016); <c>affected</c> with an action for reachable ones; everything else <c>under_investigation</c>.
/// </summary>
internal static class VexCommand
{
    public static ExitCode Run(string[] args, TextWriter output, CliContext context)
    {
        if (args.Length > 0 && args[0] == "verify")
        {
            return VexVerifyCommand.Run(args[1..], output, context);
        }

        AnalysisArgs analysis = new();
        string path = ".";
        bool pathSet = false;
        string? product = null;
        string? author = null;
        string? role = null;
        string? timestampText = null;
        string? outFile = null;
        bool sign = false;
        string? keyFile = null;
        List<string> subjectFiles = [];
        List<string> subjectDigests = [];

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];

            if (analysis.TryRead(args, ref i, arg, "vex"))
            {
                continue;
            }

            if (ReachArgs.TryValue(args, ref i, arg, "--product", null, out string? value))
            {
                product = value;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--author", null, out value))
            {
                author = value;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--role", null, out value))
            {
                role = value;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--timestamp", null, out value))
            {
                timestampText = value;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--out", "-o", out value))
            {
                outFile = value;
            }
            else if (arg == "--sign")
            {
                sign = true;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--key", null, out value))
            {
                keyFile = value;
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--subject-file", null, out value))
            {
                subjectFiles.Add(value!);
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--subject-digest", null, out value))
            {
                subjectDigests.Add(value!);
            }
            else if (ReachArgs.TryValue(args, ref i, arg, "--format", "-f", out value))
            {
                if (value != "json")
                {
                    throw new InvalidInputException("'vex' writes OpenVEX, which is JSON: --format json is the only format.");
                }
            }
            else if (arg.StartsWith('-'))
            {
                throw new InvalidInputException($"unknown option '{arg}' for 'vex'.");
            }
            else if (!pathSet)
            {
                path = arg;
                pathSet = true;
            }
            else
            {
                throw new InvalidInputException("'vex' takes at most one path.");
            }
        }

        string productValue = Required(product, "--product", "the product the statements are about, as a Package URL or an IRI (for example pkg:nuget/MyApp@1.0.0)", 500);
        string authorValue = Required(author, "--author", "who makes these statements (a person, a team, or an organization)", 200);

        if (role is not null && (role.Length > 200 || role.Any(char.IsControl)))
        {
            throw new InvalidInputException("--role is too long or contains control characters.");
        }

        if (!sign && (keyFile is not null || subjectFiles.Count > 0 || subjectDigests.Count > 0))
        {
            throw new InvalidInputException("--key, --subject-file, and --subject-digest only apply together with --sign.");
        }

        List<AttestationSubject> subjects = [];

        if (sign)
        {
            if (keyFile is null)
            {
                throw new InvalidInputException("--sign needs --key <private key file> (an ECDSA P-256 key in PEM form).");
            }

            subjects = ReadSubjects(subjectFiles, subjectDigests, productValue, context);
        }

        DateTimeOffset timestamp;

        if (timestampText is null)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            timestamp = new DateTimeOffset(now.Year, now.Month, now.Day, now.Hour, now.Minute, now.Second, TimeSpan.Zero);
        }
        else if (!DateTimeOffset.TryParse(timestampText, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out timestamp))
        {
            throw new InvalidInputException("--timestamp must be an RFC 3339 date and time, for example 2026-11-05T12:00:00Z.");
        }

        ToolInfo tool = new(ProductInfo.CommandName, VersionInfo.Current);
        RankPipelineOutcome pipeline = RankPipeline.Run(
            analysis.ToPipelineOptions("vex", Path.GetFullPath(path, context.WorkingDirectory), context),
            tool,
            new AnalyzerProcess(),
            Environment.GetEnvironmentVariable,
            AppContext.BaseDirectory);

        string json = OpenVexWriter.Serialize(
            pipeline.Ranking.Result,
            pipeline.Reach?.Result,
            new OpenVexOptions(productValue, authorValue, role, timestamp, $"{tool.Name} {tool.Version}"));

        string written = json;

        if (sign)
        {
            AuditSigner signer;

            try
            {
                signer = AuditSigner.LoadPrivate(Path.GetFullPath(keyFile!, context.WorkingDirectory));
            }
            catch (AuditException ex)
            {
                throw new InvalidInputException(ex.Message, ex);
            }

            using (signer)
            {
                // The statement carries the OpenVEX document as its predicate; the envelope signs the statement (ADR 0021).
                written = Dsse.Sign(signer, InTotoStatement.PayloadType, InTotoStatement.Create(subjects, OpenVexWriter.Context, json));
            }
        }

        List<AuditChange> changes = [];

        if (outFile is not null)
        {
            string outPath = Path.GetFullPath(outFile, context.WorkingDirectory);
            bool existed = File.Exists(outPath);

            try
            {
                File.WriteAllText(outPath, written, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new InvalidInputException($"cannot write '{outFile}' ({ex.Message})", ex);
            }

            changes.Add(new AuditChange(outFile.Replace('\\', '/'), existed ? "existing file" : null, "written"));
        }

        AuditRecorder.RecordIfEnabled(
            context,
            new AuditDraft("vex", ArgRedactor.Redact(args), pipeline.Ranking.InputsDigest, Digest.Sha256Hex(written), changes));

        if (outFile is null)
        {
            output.Write(written);
        }
        else
        {
            string what = sign ? "signed OpenVEX (DSSE envelope, in-toto statement)" : "OpenVEX";
            output.Write($"Wrote {what} to {outFile} ({pipeline.Ranking.Result.Findings.Count} statement(s))\n");
        }

        return ExitCode.Success;
    }

    /// <summary>
    /// What a signed statement is about: files (hashed here, so a digest cannot be mistyped) and digests given as sha256:hex. At least one
    /// is needed: a signature over nothing in particular is not an attestation of anything.
    /// </summary>
    private static List<AttestationSubject> ReadSubjects(List<string> files, List<string> digests, string product, CliContext context)
    {
        List<AttestationSubject> subjects = [];

        foreach (string file in files)
        {
            string full = Path.GetFullPath(file, context.WorkingDirectory);

            try
            {
                using FileStream stream = File.OpenRead(full);
                subjects.Add(new AttestationSubject(Path.GetFileName(full), Convert.ToHexStringLower(SHA256.HashData(stream))));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new InvalidInputException($"cannot read the subject file '{TerminalText.Safe(file, 80)}' ({ex.Message})", ex);
            }
        }

        foreach (string digest in digests)
        {
            string hex = digest.StartsWith("sha256:", StringComparison.Ordinal) ? digest["sha256:".Length..] : string.Empty;

            if (!InTotoStatement.IsDigest(hex))
            {
                throw new InvalidInputException("--subject-digest must be sha256: followed by 64 lowercase hexadecimal digits.");
            }

            subjects.Add(new AttestationSubject(product, hex));
        }

        if (subjects.Count == 0)
        {
            throw new InvalidInputException("--sign needs the artifact the statements are about: --subject-file <file> (for example the built package or the lockfile) or --subject-digest sha256:<hex>.");
        }

        return subjects;
    }

    private static string Required(string? value, string option, string meaning, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidInputException($"'vex' needs {option}: {meaning}.");
        }

        if (value.Length > maxLength || value.Any(char.IsControl))
        {
            throw new InvalidInputException($"{option} is too long or contains control characters.");
        }

        return value;
    }
}
