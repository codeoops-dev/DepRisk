namespace DepRisk.Audit;

/// <summary>
/// The <c>.deprisk</c> directory of a project: signing key, public key, and the audit log.
/// The private key is created with owner-only permissions where the OS supports it and is excluded from Git.
/// </summary>
public sealed class AuditStore
{
    public const string DirectoryName = ".deprisk";
    public const string PrivateKeyFileName = "audit.key";
    public const string PublicKeyFileName = "audit.pub";
    public const string LogFileName = "audit.log";

    private const string GitIgnoreFileName = ".gitignore";

    public AuditStore(string directory)
    {
        Directory = Path.GetFullPath(directory);
    }

    public string Directory { get; }

    public string PrivateKeyPath => Path.Combine(Directory, PrivateKeyFileName);

    public string PublicKeyPath => Path.Combine(Directory, PublicKeyFileName);

    public string LogPath => Path.Combine(Directory, LogFileName);

    /// <summary>True if <c>&lt;projectDirectory&gt;/.deprisk</c> already holds a key or a log.</summary>
    public static bool IsInitialized(string projectDirectory)
    {
        AuditStore store = new(Path.Combine(projectDirectory, DirectoryName));
        return File.Exists(store.PrivateKeyPath) || File.Exists(store.LogPath) || File.Exists(store.PublicKeyPath);
    }

    /// <summary>Looks for a store in <paramref name="startDirectory"/> and then in each parent directory.</summary>
    public static AuditStore? Find(string startDirectory)
    {
        DirectoryInfo? current = new(Path.GetFullPath(startDirectory));

        while (current is not null)
        {
            if (IsInitialized(current.FullName))
            {
                return new AuditStore(Path.Combine(current.FullName, DirectoryName));
            }

            current = current.Parent;
        }

        return null;
    }

    /// <summary>
    /// Creates the directory, a fresh key pair, and a <c>.gitignore</c> that keeps the private key out of Git.
    /// Never overwrites an existing file.
    /// </summary>
    public static AuditStore Initialize(string projectDirectory, out AuditSigner signer)
    {
        AuditStore store = new(Path.Combine(projectDirectory, DirectoryName));

        if (IsInitialized(projectDirectory))
        {
            throw new AuditException($"already initialized: {store.Directory}");
        }

        System.IO.Directory.CreateDirectory(store.Directory);
        signer = AuditSigner.Generate();

        try
        {
            WriteNew(store.PrivateKeyPath, signer.ExportPrivatePem(), ownerOnly: true);
            WriteNew(store.PublicKeyPath, signer.ExportPublicPem(), ownerOnly: false);
            WriteNew(Path.Combine(store.Directory, GitIgnoreFileName), PrivateKeyFileName + "\n", ownerOnly: false);
        }
        catch
        {
            signer.Dispose();
            throw;
        }

        return store;
    }

    public AuditSigner LoadSigner()
    {
        if (!File.Exists(PrivateKeyPath))
        {
            throw new AuditException($"the signing key is missing: {PrivateKeyPath}. The audit log cannot be extended.");
        }

        return AuditSigner.LoadPrivate(PrivateKeyPath);
    }

    private static void WriteNew(string path, string content, bool ownerOnly)
    {
        FileStreamOptions options = new()
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
        };

        if (ownerOnly && !OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        try
        {
            using FileStream stream = new(path, options);
            using StreamWriter writer = new(stream, new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            writer.Write(content);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new AuditException($"cannot create '{path}' ({ex.Message})", ex);
        }
    }
}
