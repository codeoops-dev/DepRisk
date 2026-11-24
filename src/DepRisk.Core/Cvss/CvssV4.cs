using System.Globalization;

namespace DepRisk.Core.Cvss;

/// <summary>
/// CVSS v4.0 base score, a port of the reference calculator published by FIRST (https://github.com/FIRSTdotorg/cvss-v4-calculator,
/// cvss_score.js and cvss_lookup.js, BSD-2-Clause, see THIRD-PARTY-NOTICES.md): the vector is reduced to a macro vector (six
/// equivalence classes), the macro vector's score comes from the lookup table, and the score is lowered by the mean of the distances
/// to the highest-severity vector of each class. The order of the floating-point operations follows the reference, so the scores are
/// identical to its output (the tests compare them with it).
/// Only the eleven base metrics are scored, like <see cref="CvssV3"/> scores only base metrics: Threat (E), Environmental (CR, IR, AR
/// and the Modified metrics) and Supplemental metrics in a vector are checked but ignored, so the result is the base score
/// (CVSS-B). See ADR 0028.
/// </summary>
public static class CvssV4
{
    private const string Prefix = "CVSS:4.0";

    private static readonly string[] BaseMetrics = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"];

    /// <summary>The values each metric can take in a vector string, from the specification (version 4.0, tables 1 to 3).</summary>
    private static readonly Dictionary<string, string> AllowedValues = new(StringComparer.Ordinal)
    {
        // Base.
        ["AV"] = "NALP",
        ["AC"] = "LH",
        ["AT"] = "NP",
        ["PR"] = "NLH",
        ["UI"] = "NPA",
        ["VC"] = "HLN",
        ["VI"] = "HLN",
        ["VA"] = "HLN",
        ["SC"] = "HLN",
        ["SI"] = "HLN",
        ["SA"] = "HLN",

        // Threat and Environmental: checked, not scored.
        ["E"] = "XAPU",
        ["CR"] = "XHML",
        ["IR"] = "XHML",
        ["AR"] = "XHML",
        ["MAV"] = "XNALP",
        ["MAC"] = "XLH",
        ["MAT"] = "XNP",
        ["MPR"] = "XNLH",
        ["MUI"] = "XNPA",
        ["MVC"] = "XHLN",
        ["MVI"] = "XHLN",
        ["MVA"] = "XHLN",
        ["MSC"] = "XHLN",
        ["MSI"] = "XSHLN",
        ["MSA"] = "XSHLN",

        // Supplemental: checked, not scored. (Single-letter values only; U also has multi-letter values.)
        ["S"] = "XNP",
        ["AU"] = "XNY",
        ["R"] = "XAUI",
        ["V"] = "XDC",
        ["RE"] = "XLMH",
    };

    private static readonly string[] ProviderUrgency = ["X", "Clear", "Green", "Amber", "Red"];

    public static bool TryScore(string? vector, out CvssScore? score)
    {
        score = null;

        if (string.IsNullOrWhiteSpace(vector))
        {
            return false;
        }

        string[] parts = vector.Trim().Split('/');

        if (parts[0] != Prefix)
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

            if (!IsKnownValue(name, value) || !metrics.TryAdd(name, value))
            {
                return false;
            }
        }

        if (BaseMetrics.Any(m => !metrics.ContainsKey(m)))
        {
            return false;
        }

        double baseScore = Score(metrics);
        string canonical = Prefix + "/" + string.Join('/', BaseMetrics.Select(m => $"{m}:{metrics[m]}"));
        score = new CvssScore("4.0", canonical, baseScore, CvssV3.Rating(baseScore));
        return true;
    }

    private static bool IsKnownValue(string name, string value)
    {
        if (name == "U")
        {
            return ProviderUrgency.Contains(value, StringComparer.Ordinal);
        }

        return AllowedValues.TryGetValue(name, out string? allowed) && value.Length == 1 && allowed.Contains(value[0], StringComparison.Ordinal);
    }

    // ---- the score (reference: cvss_score.js) ----

    private static readonly Dictionary<string, double> AvLevels = new() { ["N"] = 0.0, ["A"] = 0.1, ["L"] = 0.2, ["P"] = 0.3 };
    private static readonly Dictionary<string, double> PrLevels = new() { ["N"] = 0.0, ["L"] = 0.1, ["H"] = 0.2 };
    private static readonly Dictionary<string, double> UiLevels = new() { ["N"] = 0.0, ["P"] = 0.1, ["A"] = 0.2 };
    private static readonly Dictionary<string, double> AcLevels = new() { ["L"] = 0.0, ["H"] = 0.1 };
    private static readonly Dictionary<string, double> AtLevels = new() { ["N"] = 0.0, ["P"] = 0.1 };
    private static readonly Dictionary<string, double> VulnImpactLevels = new() { ["H"] = 0.0, ["L"] = 0.1, ["N"] = 0.2 };
    private static readonly Dictionary<string, double> ScLevels = new() { ["H"] = 0.1, ["L"] = 0.2, ["N"] = 0.3 };
    private static readonly Dictionary<string, double> SiSaLevels = new() { ["S"] = 0.0, ["H"] = 0.1, ["L"] = 0.2, ["N"] = 0.3 };
    private static readonly Dictionary<string, double> RequirementLevels = new() { ["H"] = 0.0, ["M"] = 0.1, ["L"] = 0.2 };

    // The highest-severity vectors of each equivalence class (maxComposed in the reference).
    private static readonly string[][] Eq1Maxes = [["AV:N/PR:N/UI:N/"], ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"], ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"]];
    private static readonly string[][] Eq2Maxes = [["AC:L/AT:N/"], ["AC:H/AT:N/", "AC:L/AT:P/"]];

    private static readonly Dictionary<(int Eq3, int Eq6), string[]> Eq3Eq6Maxes = new()
    {
        [(0, 0)] = ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
        [(0, 1)] = ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"],
        [(1, 0)] = ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
        [(1, 1)] = ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"],
        [(2, 1)] = ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"],
    };

    private static readonly string[][] Eq4Maxes = [["SC:H/SI:S/SA:S/"], ["SC:H/SI:H/SA:H/"], ["SC:L/SI:L/SA:L/"]];

    // Depth of each equivalence class in steps of 0.1 (maxSeverity in the reference).
    private static readonly int[] Eq1Depth = [1, 4, 5];
    private static readonly int[] Eq2Depth = [1, 2];
    private static readonly Dictionary<(int Eq3, int Eq6), int> Eq3Eq6Depth = new() { [(0, 0)] = 7, [(0, 1)] = 6, [(1, 0)] = 8, [(1, 1)] = 8, [(2, 1)] = 10 };
    private static readonly int[] Eq4Depth = [6, 5, 4];

    /// <summary>The base score of a vector whose base metrics are all present and valid. Threat and Environmental metrics take the values of a base vector (E:A, CR/IR/AR:H, no Modified metric).</summary>
    private static double Score(Dictionary<string, string> v)
    {
        // A vector with no impact on the vulnerable or the subsequent system scores 0.
        if (new[] { "VC", "VI", "VA", "SC", "SI", "SA" }.All(m => v[m] == "N"))
        {
            return 0.0;
        }

        // Equivalence classes (macroVector in the reference), with E:A and CR, IR, AR:H, and no Modified metrics.
        int eq1 = v["AV"] == "N" && v["PR"] == "N" && v["UI"] == "N"
            ? 0
            : (v["AV"] == "N" || v["PR"] == "N" || v["UI"] == "N") && v["AV"] != "P" ? 1 : 2;
        int eq2 = v["AC"] == "L" && v["AT"] == "N" ? 0 : 1;
        int eq3 = v["VC"] == "H" && v["VI"] == "H" ? 0 : v["VC"] == "H" || v["VI"] == "H" || v["VA"] == "H" ? 1 : 2;
        int eq4 = v["SC"] == "H" || v["SI"] == "H" || v["SA"] == "H" ? 1 : 2;
        const int eq5 = 0;
        int eq6 = v["VC"] == "H" || v["VI"] == "H" || v["VA"] == "H" ? 0 : 1;

        string macro = Key(eq1, eq2, eq3, eq4, eq5, eq6);
        double value = CvssV4Lookup.Scores[macro];

        // The score of the next lower macro vector of each class; null when there is none.
        double? lowerEq1 = Lookup(eq1 + 1, eq2, eq3, eq4, eq5, eq6);
        double? lowerEq2 = Lookup(eq1, eq2 + 1, eq3, eq4, eq5, eq6);
        double? lowerEq3Eq6;

        if (eq3 == 0 && eq6 == 0)
        {
            // Two ways down: take the one with the higher score.
            double? left = Lookup(eq1, eq2, eq3, eq4, eq5, eq6 + 1);
            double? right = Lookup(eq1, eq2, eq3 + 1, eq4, eq5, eq6);
            lowerEq3Eq6 = left > right ? left : right;
        }
        else if (eq3 == 1 && eq6 == 0)
        {
            lowerEq3Eq6 = Lookup(eq1, eq2, eq3, eq4, eq5, eq6 + 1);
        }
        else if ((eq3 == 1 && eq6 == 1) || (eq3 == 0 && eq6 == 1))
        {
            lowerEq3Eq6 = Lookup(eq1, eq2, eq3 + 1, eq4, eq5, eq6);
        }
        else
        {
            lowerEq3Eq6 = Lookup(eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1);
        }

        double? lowerEq4 = Lookup(eq1, eq2, eq3, eq4 + 1, eq5, eq6);
        double? lowerEq5 = Lookup(eq1, eq2, eq3, eq4, eq5 + 1, eq6);

        // The distance of the vector from the highest-severity vector of its macro vector: the first composed maximum that is at least
        // as severe as the vector in every metric.
        double dAv = 0, dPr = 0, dUi = 0, dAc = 0, dAt = 0, dVc = 0, dVi = 0, dVa = 0, dSc = 0, dSi = 0, dSa = 0, dCr = 0, dIr = 0, dAr = 0;

        foreach (string e1 in Eq1Maxes[eq1])
        {
            foreach (string e2 in Eq2Maxes[eq2])
            {
                foreach (string e36 in Eq3Eq6Maxes[(eq3, eq6)])
                {
                    foreach (string e4 in Eq4Maxes[eq4])
                    {
                        string max = e1 + e2 + e36 + e4 + "E:A/";

                        dAv = AvLevels[v["AV"]] - AvLevels[ValueIn("AV", max)];
                        dPr = PrLevels[v["PR"]] - PrLevels[ValueIn("PR", max)];
                        dUi = UiLevels[v["UI"]] - UiLevels[ValueIn("UI", max)];
                        dAc = AcLevels[v["AC"]] - AcLevels[ValueIn("AC", max)];
                        dAt = AtLevels[v["AT"]] - AtLevels[ValueIn("AT", max)];
                        dVc = VulnImpactLevels[v["VC"]] - VulnImpactLevels[ValueIn("VC", max)];
                        dVi = VulnImpactLevels[v["VI"]] - VulnImpactLevels[ValueIn("VI", max)];
                        dVa = VulnImpactLevels[v["VA"]] - VulnImpactLevels[ValueIn("VA", max)];
                        dSc = ScLevels[v["SC"]] - ScLevels[ValueIn("SC", max)];
                        dSi = SiSaLevels[v["SI"]] - SiSaLevels[ValueIn("SI", max)];
                        dSa = SiSaLevels[v["SA"]] - SiSaLevels[ValueIn("SA", max)];

                        // CR, IR and AR are H in a base vector.
                        dCr = RequirementLevels["H"] - RequirementLevels[ValueIn("CR", max)];
                        dIr = RequirementLevels["H"] - RequirementLevels[ValueIn("IR", max)];
                        dAr = RequirementLevels["H"] - RequirementLevels[ValueIn("AR", max)];

                        if (dAv < 0 || dPr < 0 || dUi < 0 || dAc < 0 || dAt < 0 || dVc < 0 || dVi < 0 || dVa < 0 || dSc < 0 || dSi < 0 || dSa < 0 || dCr < 0 || dIr < 0 || dAr < 0)
                        {
                            continue;
                        }

                        goto Found;
                    }
                }
            }
        }

    Found:
        double distanceEq1 = dAv + dPr + dUi;
        double distanceEq2 = dAc + dAt;
        double distanceEq3Eq6 = dVc + dVi + dVa + dCr + dIr + dAr;
        double distanceEq4 = dSc + dSi + dSa;

        const double step = 0.1;
        int existing = 0;
        double normalized = 0;

        // For each class that has a lower macro vector: the available distance (the score gap to it) times the share of the class's
        // depth the vector has gone down. EQ5 is always 0 for a base vector.
        if (lowerEq1 is { } l1)
        {
            existing++;
            normalized += (value - l1) * (distanceEq1 / (Eq1Depth[eq1] * step));
        }

        if (lowerEq2 is { } l2)
        {
            existing++;
            normalized += (value - l2) * (distanceEq2 / (Eq2Depth[eq2] * step));
        }

        if (lowerEq3Eq6 is { } l36)
        {
            existing++;
            normalized += (value - l36) * (distanceEq3Eq6 / (Eq3Eq6Depth[(eq3, eq6)] * step));
        }

        if (lowerEq4 is { } l4)
        {
            existing++;
            normalized += (value - l4) * (distanceEq4 / (Eq4Depth[eq4] * step));
        }

        if (lowerEq5 is not null)
        {
            existing++;
        }

        double mean = existing == 0 ? 0 : normalized / existing;
        value -= mean;
        value = Math.Clamp(value, 0.0, 10.0);

        // JavaScript's Math.round rounds halves up.
        return Math.Floor((value * 10) + 0.5) / 10;
    }

    private static string Key(int eq1, int eq2, int eq3, int eq4, int eq5, int eq6) =>
        string.Create(CultureInfo.InvariantCulture, $"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}");

    private static double? Lookup(int eq1, int eq2, int eq3, int eq4, int eq5, int eq6) =>
        CvssV4Lookup.Scores.TryGetValue(Key(eq1, eq2, eq3, eq4, eq5, eq6), out double score) ? score : null;

    /// <summary>The value of a metric in a composed maximum vector such as <c>AV:N/PR:N/...</c>.</summary>
    private static string ValueIn(string metric, string composed)
    {
        // Each metric is searched for at the start of the string or after a '/', so "AV" is not found inside another name.
        int start = composed.StartsWith(metric + ":", StringComparison.Ordinal)
            ? metric.Length + 1
            : composed.IndexOf("/" + metric + ":", StringComparison.Ordinal) + metric.Length + 2;

        int end = composed.IndexOf('/', start);
        return composed[start..end];
    }
}
