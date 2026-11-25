using System.Text;

namespace DepRisk.Audit;

/// <summary>
/// Where the passphrase of an encrypted signing key comes from: the environment variable <c>DEPRISK_KEY_PASSPHRASE</c> (the passphrase
/// itself) or <c>DEPRISK_KEY_PASSPHRASE_FILE</c> (the path of a file that holds it). Never the command line, where it would show in
/// the process list, the shell history and the audit log. A key without a passphrase needs none of this. See ADR 0030.
/// </summary>
public static class KeyPassphrase
{
    public const string EnvironmentVariable = "DEPRISK_KEY_PASSPHRASE";
    public const string FileEnvironmentVariable = "DEPRISK_KEY_PASSPHRASE_FILE";

    /// <summary>A new encrypted key needs at least this many characters. An existing key is not held to it.</summary>
    public const int MinimumLengthForNewKey = 12;

    private const int MaxFileBytes = 1024;

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <returns>The passphrase, or null when neither variable is set.</returns>
    /// <exception cref="AuditException">Both are set, one is set but empty, or the file cannot be used. The message never holds the passphrase.</exception>
    public static string? Read(Func<string, string?> getEnvironmentVariable, string baseDirectory)
    {
        ArgumentNullException.ThrowIfNull(getEnvironmentVariable);
        ArgumentNullException.ThrowIfNull(baseDirectory);

        string? direct = getEnvironmentVariable(EnvironmentVariable);
        string? file = getEnvironmentVariable(FileEnvironmentVariable);

        if (direct is not null && file is not null)
        {
            throw new AuditException($"both {EnvironmentVariable} and {FileEnvironmentVariable} are set: use one.");
        }

        if (direct is not null)
        {
            return direct.Length == 0 ? throw new AuditException($"{EnvironmentVariable} is set but empty.") : direct;
        }

        if (file is null)
        {
            return null;
        }

        if (file.Length == 0)
        {
            throw new AuditException($"{FileEnvironmentVariable} is set but empty.");
        }

        return ReadFile(ResolvePath(file, baseDirectory));
    }

    /// <summary>
    /// A full path is used as it is: <c>Path.GetFullPath(path, basePath)</c> refuses a base that is not fully qualified (on Windows,
    /// <c>/work</c> has no drive), even when the path itself would not need it.
    /// </summary>
    internal static string ResolvePath(string path, string baseDirectory) =>
        Path.IsPathFullyQualified(path) ? Path.GetFullPath(path) : Path.GetFullPath(path, baseDirectory);

    private static string ReadFile(string path)
    {
        byte[] bytes;

        try
        {
            FileInfo info = new(path);

            if (!info.Exists)
            {
                throw new AuditException($"the passphrase file '{path}' (from {FileEnvironmentVariable}) does not exist.");
            }

            if (info.Length > MaxFileBytes)
            {
                throw new AuditException($"the passphrase file '{path}' is larger than {MaxFileBytes} bytes: it must hold the passphrase and nothing else.");
            }

            bytes = File.ReadAllBytes(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new AuditException($"cannot read the passphrase file '{path}' ({ex.Message})", ex);
        }

        string text;

        try
        {
            text = StrictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            throw new AuditException($"the passphrase file '{path}' is not valid UTF-8.");
        }
        finally
        {
            Array.Clear(bytes);
        }

        text = text.TrimStart('\uFEFF');

        // One line, with or without its line ending: what "echo secret > file" writes.
        if (text.EndsWith("\r\n", StringComparison.Ordinal))
        {
            text = text[..^2];
        }
        else if (text.EndsWith('\n'))
        {
            text = text[..^1];
        }

        if (text.Length == 0)
        {
            throw new AuditException($"the passphrase file '{path}' is empty.");
        }

        if (text.Any(c => c is '\r' or '\n'))
        {
            throw new AuditException($"the passphrase file '{path}' must hold one line.");
        }

        return text;
    }
}
