using System.Reflection;

namespace DepRisk.Cli;

internal static class VersionInfo
{
    /// <summary>Semantic version of this build (build metadata after '+' is removed).</summary>
    public static string Current
    {
        get
        {
            Assembly assembly = typeof(VersionInfo).Assembly;
            string? info = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;

            if (string.IsNullOrWhiteSpace(info))
            {
                return assembly.GetName().Version?.ToString(3) ?? "0.0.0";
            }

            int plus = info.IndexOf('+', StringComparison.Ordinal);
            return plus >= 0 ? info[..plus] : info;
        }
    }
}
