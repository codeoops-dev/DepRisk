using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using DepRisk.Audit;
using DepRisk.Data.Reach;
using DepRisk.Core;

namespace DepRisk.Cli;

/// <summary>
/// Diagnoses the installation: <c>deprisk doctor [--format table|json]</c>. At this stage it only reports facts; it never changes
/// anything and makes no network calls. The JSON form is described by schemas/doctor.v1.schema.json.
/// </summary>
internal static class DoctorCommand
{
    private enum Status
    {
        Ok,
        Info,
        Warn,
    }

    private sealed record Check(Status Status, string Name, string Detail);

    public static ExitCode Run(string[] args, TextWriter output, CliContext context)
    {
        string format = "table";

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];

            if (OptionValue.TryValue(args, ref i, arg, "--format", "-f", out string? value))
            {
                format = value!;
            }
            else if (arg.StartsWith('-'))
            {
                throw new InvalidInputException($"unknown option '{arg}' for 'doctor'.");
            }
            else
            {
                throw new InvalidInputException($"'doctor' takes no path (got '{arg}').");
            }
        }

        if (format is not ("table" or "json"))
        {
            throw new InvalidInputException($"unknown format '{format}' for 'doctor'. Available: table, json.");
        }

        List<Check> checks =
        [
            new(Status.Ok, "version", VersionInfo.Current),
            new(Status.Ok, "runtime", RuntimeInformation.FrameworkDescription),
            new(Status.Ok, "platform", $"{RuntimeInformation.OSDescription} ({RuntimeInformation.OSArchitecture})"),
            CheckAnalyzer(),
            CheckCompanion("deprisk-kernel", "verification kernel (planned, v0.4)"),
            CheckAudit(context),
            CheckConfig(context),
        ];

        // Right after the audit check it belongs to.
        if (CheckSigningKey(context) is { } keyCheck)
        {
            checks.Insert(checks.FindIndex(c => c.Name == "audit") + 1, keyCheck);
        }

        int warnings = checks.Count(c => c.Status == Status.Warn);

        if (format == "json")
        {
            WriteJson(output, checks, warnings);
            return ExitCode.Success;
        }

        output.WriteLine($"{ProductInfo.CommandName} doctor");
        output.WriteLine();

        foreach (Check check in checks)
        {
            string tag = check.Status switch
            {
                Status.Ok => " ok ",
                Status.Info => "info",
                _ => "warn",
            };

            output.WriteLine($"  [{tag}] {check.Name,-16} {check.Detail}");
        }

        output.WriteLine();
        output.WriteLine(warnings == 0 ? "No problems found." : $"{warnings} warning(s).");

        // Warnings never fail the command at this stage; hard failures will be added with the components they cover.
        return ExitCode.Success;
    }

    private static Check CheckCompanion(string name, string description)
    {
        string? path = FindExecutable(name);

        return path is null
            ? new Check(Status.Info, name, $"not installed: {description}")
            : new Check(Status.Ok, name, path);
    }

    private static Check CheckAnalyzer()
    {
        // The same places the 'reach' command looks in (the PATH is not one of them).
        try
        {
            string? path = AnalyzerLocator.Find(null, Environment.CurrentDirectory, Environment.GetEnvironmentVariable, AppContext.BaseDirectory);

            return path is null
                ? new Check(Status.Info, "deprisk-reach", $"not found: reachability analyzer (bundled with the NuGet package for {string.Join(", ", AnalyzerLocator.BundledPlatforms)}; this machine: {AnalyzerLocator.CurrentPlatform() ?? "other"}; or pass --analyzer, set {AnalyzerLocator.EnvironmentVariable}, or put it next to deprisk)")
                : new Check(Status.Ok, "deprisk-reach", path);
        }
        catch (InvalidInputException ex)
        {
            return new Check(Status.Warn, "deprisk-reach", ex.Message);
        }
    }

    private static Check CheckAudit(CliContext context)
    {
        AuditStore? store = AuditStore.Find(context.WorkingDirectory);

        return store is null
            ? new Check(Status.Info, "audit", "not initialized (run 'deprisk init' to start an audit log)")
            : new Check(Status.Ok, "audit", $"initialized: {store.Directory}");
    }

    /// <summary>
    /// The signing key of the audit store: where it is, whether it can be loaded (which is how a wrong passphrase or a key that does not
    /// belong to the store shows up), and whether an unprotected key can be read by others. Never prints a passphrase.
    /// </summary>
    private static Check? CheckSigningKey(CliContext context)
    {
        AuditStore? store = AuditStore.Find(context.WorkingDirectory);

        if (store is null)
        {
            return null;
        }

        string? configured = context.GetEnvironmentVariable(AuditStore.KeyFileEnvironmentVariable);
        bool external = !string.IsNullOrEmpty(configured);
        string keyPath = external ? Path.GetFullPath(configured!, context.WorkingDirectory) : store.PrivateKeyPath;

        if (!File.Exists(keyPath))
        {
            return new Check(
                Status.Warn,
                "audit-key",
                $"not found: {keyPath}{(external ? $" (from {AuditStore.KeyFileEnvironmentVariable})" : string.Empty)}. Commands in this project that write the audit log will stop with exit code 3");
        }

        bool encrypted;

        try
        {
            encrypted = AuditSigner.IsEncryptedKey(File.ReadAllText(keyPath));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new Check(Status.Warn, "audit-key", $"cannot read {keyPath} ({ex.Message})");
        }

        string description = encrypted ? "encrypted with a passphrase" : "not encrypted";

        try
        {
            // Loading is how a wrong passphrase, a damaged key, or a key that is not the store's shows up.
            using AuditSigner signer = store.LoadSigner(context.GetEnvironmentVariable, context.WorkingDirectory);
        }
        catch (AuditException ex)
        {
            return new Check(Status.Warn, "audit-key", $"{keyPath} ({description}) cannot be used: {ex.Message}");
        }

        if (!encrypted && SharedWithOthers(keyPath))
        {
            return new Check(Status.Warn, "audit-key", $"{keyPath} ({description}) can be read by other users of this machine; restrict it (chmod 600) or encrypt it");
        }

        string source = encrypted
            ? string.IsNullOrEmpty(context.GetEnvironmentVariable(KeyPassphrase.EnvironmentVariable))
                ? $", passphrase from {KeyPassphrase.FileEnvironmentVariable}"
                : $", passphrase from {KeyPassphrase.EnvironmentVariable}"
            : string.Empty;

        return new Check(Status.Ok, "audit-key", $"{keyPath} ({description}{source})");
    }

    private static bool SharedWithOthers(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            UnixFileMode others = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.OtherRead | UnixFileMode.OtherWrite;
            return (File.GetUnixFileMode(path) & others) != 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            return false;
        }
    }

    private static void WriteJson(TextWriter output, List<Check> checks, int warnings)
    {
        using MemoryStream stream = new();

        using (Utf8JsonWriter writer = new(stream, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", 1);

            writer.WriteStartObject("tool");
            writer.WriteString("name", ProductInfo.CommandName);
            writer.WriteString("version", VersionInfo.Current);
            writer.WriteEndObject();

            writer.WriteStartArray("checks");

            foreach (Check check in checks)
            {
                writer.WriteStartObject();
                writer.WriteString("name", check.Name);
                writer.WriteString("status", check.Status switch { Status.Ok => "ok", Status.Info => "info", _ => "warn" });
                writer.WriteString("detail", check.Detail);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteNumber("warnings", warnings);
            writer.WriteEndObject();
        }

        output.Write(Encoding.UTF8.GetString(stream.ToArray()));
        output.Write("\n");
    }

    private static Check CheckConfig(CliContext context)
    {
        string path = Path.Combine(context.WorkingDirectory, "deprisk.toml");

        return File.Exists(path)
            ? new Check(Status.Ok, "config", path)
            : new Check(Status.Info, "config", "deprisk.toml not found in the current directory (optional at this stage)");
    }

    private static string? FindExecutable(string name)
    {
        string[] candidates = OperatingSystem.IsWindows() ? [name + ".exe", name] : [name];

        List<string> directories = [AppContext.BaseDirectory];
        string? pathVariable = Environment.GetEnvironmentVariable("PATH");

        if (!string.IsNullOrEmpty(pathVariable))
        {
            directories.AddRange(pathVariable.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries));
        }

        foreach (string directory in directories)
        {
            foreach (string candidate in candidates)
            {
                try
                {
                    string full = Path.Combine(directory, candidate);

                    if (File.Exists(full))
                    {
                        return full;
                    }
                }
                catch (ArgumentException)
                {
                    // Malformed PATH entry: ignore it.
                }
            }
        }

        return null;
    }
}
