using DepRisk.Audit;

namespace DepRisk.Audit.Tests;

/// <summary>A throw-away audit store in a temporary directory.</summary>
internal sealed class TempStore : IDisposable
{
    private int _counter;

    public TempStore()
    {
        Root = Path.Combine(Path.GetTempPath(), "deprisk-audit-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Root);
        Store = AuditStore.Initialize(Root, out AuditSigner signer);
        Signer = signer;
        Log = new AuditLog(Store);
    }

    public string Root { get; }

    public AuditStore Store { get; }

    public AuditSigner Signer { get; }

    public AuditLog Log { get; }

    public static AuditEnvironment Environment(int second = 0) =>
        new(new DateTimeOffset(2026, 10, 27, 12, 0, second, TimeSpan.Zero), "alice", "host-1", "/work/project", "0123456789abcdef0123456789abcdef01234567");

    public AuditEntry Append(string command = "scan", params string[] args)
    {
        _counter++;
        AuditDraft draft = new(
            command,
            args,
            new string('a', 64),
            new string('b', 64),
            [new AuditChange($"file-{_counter}.json", null, "written")]);

        return Log.Append(draft, Environment(_counter % 60), Signer);
    }

    public string[] Lines() => File.ReadAllLines(Store.LogPath);

    public void WriteLines(IEnumerable<string> lines) => File.WriteAllText(Store.LogPath, string.Concat(lines.Select(l => l + "\n")));

    public AuditVerification Verify(string? head = null) => AuditLog.Verify(Store.LogPath, Signer, head);

    public void Dispose()
    {
        Signer.Dispose();

        if (Directory.Exists(Root))
        {
            Directory.Delete(Root, recursive: true);
        }
    }
}
