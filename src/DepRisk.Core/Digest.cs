using System.Security.Cryptography;
using System.Text;

namespace DepRisk.Core;

/// <summary>SHA-256 helpers. All digests in DepRisk are lowercase hexadecimal, 64 characters.</summary>
public static class Digest
{
    /// <summary>The "previous hash" of the first audit entry.</summary>
    public static readonly string ZeroHash = new('0', 64);

    public static string Sha256Hex(ReadOnlySpan<byte> data) => Convert.ToHexStringLower(SHA256.HashData(data));

    public static string Sha256Hex(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        return Sha256Hex(Encoding.UTF8.GetBytes(text));
    }

    /// <summary>True for exactly 64 lowercase hexadecimal characters.</summary>
    public static bool IsSha256Hex(string? value)
    {
        if (value is null || value.Length != 64)
        {
            return false;
        }

        foreach (char c in value)
        {
            if (c is not ((>= '0' and <= '9') or (>= 'a' and <= 'f')))
            {
                return false;
            }
        }

        return true;
    }
}
