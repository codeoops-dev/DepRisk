using System.Numerics;

namespace DepRisk.Core.Risk;

/// <summary>
/// A small, fully specified pseudo-random generator (xoshiro256**, seeded through SplitMix64), so that the same seed gives the
/// same numbers on every platform and every .NET version. <see cref="System.Random"/> is not used because its algorithm is not part
/// of its contract. Not for cryptography.
/// </summary>
public sealed class Prng
{
    private ulong _s0;
    private ulong _s1;
    private ulong _s2;
    private ulong _s3;

    public Prng(ulong seed)
    {
        ulong state = seed;
        _s0 = SplitMix(ref state);
        _s1 = SplitMix(ref state);
        _s2 = SplitMix(ref state);
        _s3 = SplitMix(ref state);
    }

    /// <summary>A stream seed for one item, so that adding or removing other items does not change its numbers.</summary>
    public static ulong StreamSeed(ulong seed, string key)
    {
        ArgumentNullException.ThrowIfNull(key);
        byte[] hash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(key));
        ulong keyBits = BitConverter.ToUInt64(hash, 0);
        ulong state = seed ^ (keyBits * 0x9E3779B97F4A7C15UL);
        return SplitMix(ref state);
    }

    public ulong NextUInt64()
    {
        ulong result = BitOperations.RotateLeft(_s1 * 5, 7) * 9;
        ulong t = _s1 << 17;

        _s2 ^= _s0;
        _s3 ^= _s1;
        _s1 ^= _s2;
        _s0 ^= _s3;
        _s2 ^= t;
        _s3 = BitOperations.RotateLeft(_s3, 45);

        return result;
    }

    /// <summary>A uniform number in the open interval (0, 1): never exactly 0 or 1, so that logarithms and powers are safe.</summary>
    public double NextOpenUnit() => (((NextUInt64() >> 11) + 0.5) * (1.0 / 9007199254740992.0));

    /// <summary>A standard normal number (Marsaglia's polar method).</summary>
    public double NextNormal()
    {
        double u;
        double v;
        double s;

        do
        {
            u = (2.0 * NextOpenUnit()) - 1.0;
            v = (2.0 * NextOpenUnit()) - 1.0;
            s = (u * u) + (v * v);
        }
        while (s >= 1.0 || s == 0.0);

        return u * Math.Sqrt(-2.0 * Math.Log(s) / s);
    }

    /// <summary>A Gamma(shape, 1) number (Marsaglia and Tsang; for a shape below 1 the usual boost).</summary>
    public double NextGamma(double shape)
    {
        if (shape < 1.0)
        {
            return NextGamma(shape + 1.0) * Math.Pow(NextOpenUnit(), 1.0 / shape);
        }

        double d = shape - (1.0 / 3.0);
        double c = 1.0 / Math.Sqrt(9.0 * d);

        while (true)
        {
            double x = NextNormal();
            double v = 1.0 + (c * x);

            if (v <= 0.0)
            {
                continue;
            }

            v = v * v * v;
            double u = NextOpenUnit();

            if (u < 1.0 - (0.0331 * x * x * x * x) || Math.Log(u) < (0.5 * x * x) + (d * (1.0 - v + Math.Log(v))))
            {
                return d * v;
            }
        }
    }

    /// <summary>A Beta(alpha, beta) number in [0, 1].</summary>
    public double NextBeta(double alpha, double beta)
    {
        double x = NextGamma(alpha);
        double y = NextGamma(beta);
        double sum = x + y;

        return sum > 0.0 ? x / sum : alpha / (alpha + beta);
    }

    private static ulong SplitMix(ref ulong state)
    {
        state += 0x9E3779B97F4A7C15UL;
        ulong z = state;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
        return z ^ (z >> 31);
    }
}
