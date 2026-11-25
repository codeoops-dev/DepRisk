using System.Globalization;
using System.Text;
using DepRisk.Core;

namespace DepRisk.Audit;

/// <summary>
/// Appends to and verifies <c>audit.log</c>: one canonical JSON entry per line, each carrying the SHA-256 of the
/// previous line ("prevHash") and an ECDSA signature. Appends take an exclusive lock, so parallel runs never
/// produce duplicate sequence numbers or a forked chain.
/// </summary>
public sealed class AuditLog
{
    private const int MaxLineBytes = 1024 * 1024;
    private const int BlockBytes = 64 * 1024;

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private readonly string _logPath;

    public AuditLog(AuditStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        _logPath = store.LogPath;
    }

    public AuditEntry Append(AuditDraft draft, AuditEnvironment environment, AuditSigner signer)
    {
        ArgumentNullException.ThrowIfNull(draft);
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentNullException.ThrowIfNull(signer);

        using FileStream stream = OpenExclusive(_logPath);
        (int lastSeq, string previousHash) = ReadHead(stream);

        AuditEntry unsigned = new(
            lastSeq + 1,
            environment.Timestamp.UtcDateTime.ToString(AuditEntryParser.TimestampFormat, CultureInfo.InvariantCulture),
            environment.Actor,
            environment.Host,
            environment.WorkingDirectory,
            environment.GitCommit,
            draft.Command,
            draft.Args,
            draft.InputsDigest,
            draft.OutputsDigest,
            draft.Changes,
            previousHash,
            Signature: string.Empty);

        AuditEntry entry = unsigned with { Signature = signer.Sign(CanonicalJson.Body(unsigned)) };
        byte[] line = Encoding.UTF8.GetBytes(CanonicalJson.Full(entry) + "\n");

        stream.Seek(0, SeekOrigin.End);
        stream.Write(line);
        stream.Flush(flushToDisk: true);

        return entry;
    }

    /// <summary>
    /// Checks every entry: strict format, canonical form, sequence, hash chain, and signature.
    /// If <paramref name="expectedHead"/> is given, the hash of the last entry must equal it; this is the only way to
    /// notice that entries were cut off the end, which a chain alone cannot show.
    /// The log is read once, in blocks, and only the line being checked is held: the memory used does not grow with the log. It is read
    /// as it was when verification began (nothing appended later is looked at), and no lock is taken, so a command that appends an entry
    /// is never made to wait for a long verification.
    /// </summary>
    public static AuditVerification Verify(string logPath, AuditSigner verifier, string? expectedHead = null)
    {
        ArgumentNullException.ThrowIfNull(logPath);
        ArgumentNullException.ThrowIfNull(verifier);

        if (!File.Exists(logPath))
        {
            return AuditVerification.Failure(0, $"audit log not found: {logPath}", 0, Digest.ZeroHash);
        }

        FileStream stream;

        try
        {
            stream = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, BlockBytes, FileOptions.SequentialScan);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return AuditVerification.Failure(0, $"cannot read the audit log '{logPath}' ({ex.Message})", 0, Digest.ZeroHash);
        }

        using (stream)
        {
            long length = stream.Length;
            string head = Digest.ZeroHash;
            int entries = 0;

            if (length > 0)
            {
                stream.Seek(length - 1, SeekOrigin.Begin);

                if (stream.ReadByte() != '\n')
                {
                    return AuditVerification.Failure(
                        CountLines(stream, length) + 1,
                        "the last entry is incomplete (no line ending): the log was cut off or a write was interrupted",
                        entries,
                        head);
                }

                stream.Seek(0, SeekOrigin.Begin);
            }

            byte[] block = new byte[BlockBytes];
            byte[] line = new byte[4096];
            int lineLength = 0;
            bool lineTooLarge = false;
            int lineNumber = 0;
            long remaining = length;

            while (remaining > 0)
            {
                int read = stream.Read(block, 0, (int)Math.Min(block.Length, remaining));

                if (read <= 0)
                {
                    return AuditVerification.Failure(lineNumber + 1, "the log was shortened while it was read", entries, head);
                }

                remaining -= read;
                int offset = 0;

                while (offset < read)
                {
                    int newline = Array.IndexOf(block, (byte)'\n', offset, read - offset);
                    int segmentLength = (newline < 0 ? read : newline) - offset;

                    // Only a line that can still be a valid entry is kept; a longer one is counted as too large and skipped.
                    if (!lineTooLarge)
                    {
                        if (lineLength + segmentLength > MaxLineBytes)
                        {
                            lineTooLarge = true;
                        }
                        else
                        {
                            if (lineLength + segmentLength > line.Length)
                            {
                                Array.Resize(ref line, Math.Min(MaxLineBytes, Math.Max(line.Length * 2, lineLength + segmentLength)));
                            }

                            Buffer.BlockCopy(block, offset, line, lineLength, segmentLength);
                            lineLength += segmentLength;
                        }
                    }

                    if (newline < 0)
                    {
                        break;
                    }

                    lineNumber++;
                    ReadOnlySpan<byte> lineBytes = line.AsSpan(0, lineLength);
                    string? failure = lineTooLarge ? "entry is too large" : CheckLine(lineBytes, entries + 1, head, verifier);

                    if (failure is not null)
                    {
                        return AuditVerification.Failure(lineNumber, failure, entries, head);
                    }

                    head = Digest.Sha256Hex(lineBytes);
                    entries++;
                    lineLength = 0;
                    lineTooLarge = false;
                    offset = newline + 1;
                }
            }

            if (expectedHead is not null && !string.Equals(expectedHead, head, StringComparison.Ordinal))
            {
                return AuditVerification.Failure(
                    0, $"the head of the log ({head}) differs from the expected head: entries were removed or the log was replaced", entries, head);
            }

            return new AuditVerification(true, entries, head, null, 0);
        }
    }

    private static string? CheckLine(ReadOnlySpan<byte> lineBytes, int expectedSeq, string expectedPrevHash, AuditSigner verifier)
    {
        if (lineBytes.Length > MaxLineBytes)
        {
            return "entry is too large";
        }

        string text;

        try
        {
            text = StrictUtf8.GetString(lineBytes);
        }
        catch (DecoderFallbackException)
        {
            return "entry is not valid UTF-8";
        }

        if (!AuditEntryParser.TryParse(text, out AuditEntry? entry, out string error) || entry is null)
        {
            return error;
        }

        if (entry.Seq != expectedSeq)
        {
            return $"sequence number is {entry.Seq}, expected {expectedSeq}: an entry was removed, added, or reordered";
        }

        if (!string.Equals(entry.PrevHash, expectedPrevHash, StringComparison.Ordinal))
        {
            return "'prevHash' does not match the previous entry: the chain is broken";
        }

        if (!string.Equals(CanonicalJson.Full(entry), text, StringComparison.Ordinal))
        {
            return "entry is not in canonical form (it was edited or re-serialized)";
        }

        if (!verifier.Verify(CanonicalJson.Body(entry), entry.Signature))
        {
            return "signature is invalid: the entry was changed or was not signed by this key";
        }

        return null;
    }

    /// <summary>The number of line endings in the first <paramref name="length"/> bytes; only used to say where an incomplete log ends.</summary>
    private static int CountLines(FileStream stream, long length)
    {
        stream.Seek(0, SeekOrigin.Begin);
        byte[] block = new byte[BlockBytes];
        int count = 0;
        long remaining = length;

        while (remaining > 0)
        {
            int read = stream.Read(block, 0, (int)Math.Min(block.Length, remaining));

            if (read <= 0)
            {
                break;
            }

            remaining -= read;
            count += block.AsSpan(0, read).Count((byte)'\n');
        }

        return count;
    }

    private static FileStream OpenExclusive(string path)
    {
        DateTime deadline = DateTime.UtcNow.AddSeconds(15);

        while (true)
        {
            try
            {
                return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException) when (DateTime.UtcNow < deadline)
            {
                Thread.Sleep(Random.Shared.Next(5, 30));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw new AuditException($"cannot open the audit log '{path}' for writing ({ex.Message})", ex);
            }
        }
    }

    /// <summary>Reads the sequence number of the last entry and the hash that the next entry must carry.</summary>
    private static (int Seq, string Hash) ReadHead(FileStream stream)
    {
        if (stream.Length == 0)
        {
            return (0, Digest.ZeroHash);
        }

        byte[] line = ReadLastLine(stream);

        if (!AuditEntryParser.TryParse(Encoding.UTF8.GetString(line), out AuditEntry? last, out string error) || last is null)
        {
            throw new AuditException($"the last audit entry cannot be read ({error}). Run 'deprisk audit verify'.");
        }

        return (last.Seq, Digest.Sha256Hex(line));
    }

    private static byte[] ReadLastLine(FileStream stream)
    {
        long length = stream.Length;
        stream.Seek(length - 1, SeekOrigin.Begin);

        if (stream.ReadByte() != '\n')
        {
            throw new AuditException("the audit log ends with an incomplete entry. Run 'deprisk audit verify'.");
        }

        long newlinePosition = length - 1;
        long lineStart = 0;
        long cursor = newlinePosition;
        byte[] buffer = new byte[4096];

        while (cursor > 0)
        {
            int toRead = (int)Math.Min(buffer.Length, cursor);
            stream.Seek(cursor - toRead, SeekOrigin.Begin);
            stream.ReadExactly(buffer, 0, toRead);

            int index = Array.LastIndexOf(buffer, (byte)'\n', toRead - 1, toRead);

            if (index >= 0)
            {
                lineStart = cursor - toRead + index + 1;
                break;
            }

            cursor -= toRead;
        }

        long lineLength = newlinePosition - lineStart;

        if (lineLength <= 0 || lineLength > MaxLineBytes)
        {
            throw new AuditException("the last audit entry has an invalid size. Run 'deprisk audit verify'.");
        }

        byte[] line = new byte[lineLength];
        stream.Seek(lineStart, SeekOrigin.Begin);
        stream.ReadExactly(line, 0, line.Length);
        return line;
    }
}
