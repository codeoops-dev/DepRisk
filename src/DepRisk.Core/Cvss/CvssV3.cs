using System.Globalization;

namespace DepRisk.Core.Cvss;

/// <summary>A CVSS v3.x base score computed from a vector string.</summary>
public sealed record CvssScore(string Version, string Vector, double BaseScore, string Rating);

/// <summary>
/// CVSS v3.0 / v3.1 base score, implemented from the FIRST specification (section 7: base equations, appendix A: roundup).
/// Only the eight base metrics are used; temporal and environmental metrics in a vector are ignored.
/// CVSS v4.0 and v2 vectors are not scored here (they are carried as published, see ADR 0007).
/// </summary>
public static class CvssV3
{
    private static readonly string[] BaseMetrics = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];

    public static bool TryScore(string? vector, out CvssScore? score)
    {
        score = null;

        if (string.IsNullOrWhiteSpace(vector))
        {
            return false;
        }

        string[] parts = vector.Trim().Split('/');
        string prefix = parts[0];

        if (prefix is not ("CVSS:3.1" or "CVSS:3.0"))
        {
            return false;
        }

        Dictionary<string, string> metrics = new(StringComparer.Ordinal);

        for (int i = 1; i < parts.Length; i++)
        {
            int colon = parts[i].IndexOf(':', StringComparison.Ordinal);

            if (colon <= 0 || colon == parts[i].Length - 1)
            {
                return false;
            }

            string name = parts[i][..colon];
            string value = parts[i][(colon + 1)..];

            if (!metrics.TryAdd(name, value))
            {
                return false;
            }
        }

        if (BaseMetrics.Any(m => !metrics.ContainsKey(m)))
        {
            return false;
        }

        if (!TryWeights(metrics, out double av, out double ac, out double pr, out double ui, out bool scopeChanged,
                out double c, out double i2, out double a))
        {
            return false;
        }

        double iss = 1 - ((1 - c) * (1 - i2) * (1 - a));

        double impact = scopeChanged
            ? (7.52 * (iss - 0.029)) - (3.25 * Math.Pow(iss - 0.02, 15))
            : 6.42 * iss;

        double exploitability = 8.22 * av * ac * pr * ui;

        double baseScore;

        if (impact <= 0)
        {
            baseScore = 0;
        }
        else if (scopeChanged)
        {
            baseScore = Roundup(Math.Min(1.08 * (impact + exploitability), 10));
        }
        else
        {
            baseScore = Roundup(Math.Min(impact + exploitability, 10));
        }

        string canonical = prefix + "/" + string.Join('/', BaseMetrics.Select(m => $"{m}:{metrics[m]}"));
        score = new CvssScore(prefix["CVSS:".Length..], canonical, baseScore, Rating(baseScore));
        return true;
    }

    /// <summary>The qualitative severity rating of the specification (section 5).</summary>
    public static string Rating(double baseScore) => baseScore switch
    {
        0 => "NONE",
        < 4.0 => "LOW",
        < 7.0 => "MEDIUM",
        < 9.0 => "HIGH",
        _ => "CRITICAL",
    };

    /// <summary>Smallest number with one decimal that is greater than or equal to the input (specification appendix A, v3.1 form).</summary>
    public static double Roundup(double input)
    {
        long scaled = (long)Math.Round(input * 100000, MidpointRounding.AwayFromZero);

        return scaled % 10000 == 0
            ? scaled / 100000.0
            : (Math.Floor(scaled / 10000.0) + 1) / 10.0;
    }

    private static bool TryWeights(
        Dictionary<string, string> m,
        out double av,
        out double ac,
        out double pr,
        out double ui,
        out bool scopeChanged,
        out double c,
        out double i,
        out double a)
    {
        av = ac = pr = ui = c = i = a = 0;
        scopeChanged = false;

        switch (m["S"])
        {
            case "U":
                break;
            case "C":
                scopeChanged = true;
                break;
            default:
                return false;
        }

        switch (m["AV"])
        {
            case "N": av = 0.85; break;
            case "A": av = 0.62; break;
            case "L": av = 0.55; break;
            case "P": av = 0.2; break;
            default: return false;
        }

        switch (m["AC"])
        {
            case "L": ac = 0.77; break;
            case "H": ac = 0.44; break;
            default: return false;
        }

        switch (m["PR"])
        {
            case "N": pr = 0.85; break;
            case "L": pr = scopeChanged ? 0.68 : 0.62; break;
            case "H": pr = scopeChanged ? 0.5 : 0.27; break;
            default: return false;
        }

        switch (m["UI"])
        {
            case "N": ui = 0.85; break;
            case "R": ui = 0.62; break;
            default: return false;
        }

        return TryImpactWeight(m["C"], out c) && TryImpactWeight(m["I"], out i) && TryImpactWeight(m["A"], out a);
    }

    private static bool TryImpactWeight(string value, out double weight)
    {
        weight = value switch
        {
            "H" => 0.56,
            "L" => 0.22,
            "N" => 0,
            _ => -1,
        };

        return weight >= 0;
    }

    /// <summary>Formats a score the way it is published: one decimal, invariant culture.</summary>
    public static string Format(double score) => score.ToString("0.0", CultureInfo.InvariantCulture);
}
