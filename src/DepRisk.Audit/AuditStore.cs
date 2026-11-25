namespace DepRisk.Audit;

/// <summary>
/// The <c>.deprisk</c> directory of a project: signing key, public key, and the audit log.
/// The private key is created with owner-only permissions where the OS supports it and is excluded from Git. It can be encrypted with
/// a passphrase and can live outside the directory (ADR 0030).
/// </summary>
public sealed class AuditStore
{
    public const string DirectoryName = ".deprisk";
    public const string PrivateKeyFileName = "audit.key";
    public const string PublicKeyFileName = "audit.pub";
    public const string LogFileName = "audit.log";

    /// <summary>The environment variable that names the private key when it is not in the directory (<c>deprisk init --key-file</c>).</summary>
    public const string KeyFileEnvironmentVariable = "DEPRISK_KEY_FILE";

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
    public static AuditStore Initialize(string projectDirectory, out AuditSigner signer) =>
        Initialize(projectDirectory, out signer, keyFile: null, passphrase: null);

    /// <param name="keyFile">Where to write the private key instead of the directory: a full path in a directory that exists, of a file that does not.</param>
    /// <param name="passphrase">Encrypts the private key with it when not null (at least <see cref="KeyPassphrase.MinimumLengthForNewKey"/> characters).</param>
    public static AuditStore Initialize(string projectDirectory, out AuditSigner signer, string? keyFile, string? passphrase)
    {
        AuditStore store = new(Path.Combine(projectDirectory, DirectoryName));

        if (IsInitialized(projectDirectory))
        {
            throw new AuditException($"already initialized: {store.Directory}");
        }

        if (passphrase is not null && passphrase.Length < KeyPassphrase.MinimumLengthForNewKey)
        {
            throw new AuditException($"the passphrase of a new key needs at least {KeyPassphrase.MinimumLengthForNewKey} characters.");
        }

        string privateKeyPath = keyFile is null ? store.PrivateKeyPath : Path.GetFullPath(keyFile);

        if (keyFile is not null && !System.IO.Directory.Exists(Path.GetDirectoryName(privateKeyPath)))
        {
            throw new AuditException($"the directory for the key file does not exist: {Path.GetDirectoryName(privateKeyPath)}");
        }

        System.IO.Directory.CreateDirectory(store.Directory);
        signer = AuditSigner.Generate();

        try
        {
            string privatePem = passphrase is null ? signer.ExportPrivatePem() : signer.ExportEncryptedPrivatePem(passphrase);

            WriteNew(privateKeyPath, privatePem, ownerOnly: true);
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

    /// <summary>
    /// Loads the signing key: the file named by <see cref="KeyFileEnvironmentVariable"/> if it is set, else the one in the directory.
    /// An encrypted key takes its passphrase from <see cref="KeyPassphrase"/>. A key from <see cref="KeyFileEnvironmentVariable"/> must be
    /// the one the public key of the directory belongs to, or the entries it signs would never verify.
    /// </summary>
    public AuditSigner LoadSigner(Func<string, string?>? getEnvironmentVariable = null, string? baseDirectory = null)
    {
        Func<string, string?> environment = getEnvironmentVariable ?? Environment.GetEnvironmentVariable;
        string baseDir = baseDirectory ?? System.IO.Directory.GetCurrentDirectory();

        string? configured = environment(KeyFileEnvironmentVariable);
        bool external = !string.IsNullOrEmpty(configured);
        string keyPath = external ? KeyPassphrase.ResolvePath(configured!, baseDir) : PrivateKeyPath;

        if (!File.Exists(keyPath))
        {
            throw new AuditException(
                external
                    ? $"the signing key is missing: {keyPath} (from {KeyFileEnvironmentVariable}). The audit log cannot be extended."
                    : $"the signing key is missing: {keyPath}. The audit log cannot be extended.");
        }

        AuditSigner signer = AuditSigner.LoadPrivate(keyPath, () => KeyPassphrase.Read(environment, baseDir));

        if (external && File.Exists(PublicKeyPath))
        {
            using AuditSigner expected = AuditSigner.LoadPublic(PublicKeyPath);

            if (expected.KeyId() != signer.KeyId())
            {
                signer.Dispose();
                throw new AuditException($"the key in {KeyFileEnvironmentVariable} ({keyPath}) is not the key of this audit store ({PublicKeyPath}): its entries would not verify.");
            }
        }

        return signer;
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
