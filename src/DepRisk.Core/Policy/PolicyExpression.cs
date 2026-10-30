using System.Globalization;
using DepRisk.Core.Model;
using DepRisk.Core.Ranking;

namespace DepRisk.Core.Policy;

/// <summary>
/// A policy gate: <c>--fail-on</c> expression. Syntax: clauses separated by commas (any clause may fail the gate);
/// each clause is terms joined by '&amp;' (all terms must hold for the same finding).
/// Terms: <c>any</c>, <c>kev</c>, <c>ransomware</c>, <c>direct</c>, <c>fixable</c>,
/// <c>cvss&gt;=N</c>, <c>cvss&gt;N</c> (0 to 10), <c>epss&gt;=P</c>, <c>epss&gt;P</c> (0 to 1),
/// <c>severity&gt;=LEVEL</c> (low, moderate or medium, high, critical).
/// A term about a signal that is not available for a finding is false for that finding (never "zero").
/// Example: <c>kev&amp;fixable,cvss&gt;=9</c>. Reachability terms do not exist yet and are rejected.
/// </summary>
public sealed class PolicyExpression
{
    private readonly List<List<Term>> _clauses;

    private PolicyExpression(string text, List<List<Term>> clauses)
    {
        Text = text;
        _clauses = clauses;
    }

    public string Text { get; }

    public static bool TryParse(string? text, out PolicyExpression? expression, out string error)
    {
        expression = null;
        error = string.Empty;

        if (string.IsNullOrWhiteSpace(text))
        {
            error = "the policy expression is empty";
            return false;
        }

        List<List<Term>> clauses = [];

        foreach (string clauseText in text.Split(','))
        {
            List<Term> terms = [];

            foreach (string termText in clauseText.Split('&'))
            {
                if (!Term.TryParse(termText.Trim(), out Term? term, out string termError))
                {
                    error = termError;
                    return false;
                }

                terms.Add(term!);
            }

            clauses.Add(terms);
        }

        expression = new PolicyExpression(text.Trim(), clauses);
        return true;
    }

    /// <summary>True if any clause holds for the finding.</summary>
    public bool Matches(RankedFinding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        return _clauses.Any(clause => clause.All(term => term.Holds(finding)));
    }

    /// <summary>The findings that trip the gate, in the order given.</summary>
    public IReadOnlyList<RankedFinding> Evaluate(IEnumerable<RankedFinding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);
        return findings.Where(Matches).ToList();
    }

    private sealed class Term
    {
        private readonly Func<RankedFinding, bool> _predicate;

        private Term(Func<RankedFinding, bool> predicate) => _predicate = predicate;

        public bool Holds(RankedFinding finding) => _predicate(finding);

        public static bool TryParse(string text, out Term? term, out string error)
        {
            term = null;
            error = string.Empty;

            if (text.Length == 0)
            {
                error = "empty term (check for a stray ',' or '&')";
                return false;
            }

            string lower = text.ToLowerInvariant();

            switch (lower)
            {
                case "any":
                    term = new Term(_ => true);
                    return true;
                case "kev":
                    term = new Term(f => f.Signals.Kev is not null);
                    return true;
                case "ransomware":
                    term = new Term(f => f.Signals.Kev is { KnownRansomwareUse: true });
                    return true;
                case "direct":
                    term = new Term(f => f.Locations.Any(l => l.IsDirect));
                    return true;
                case "fixable":
                    term = new Term(f => f.FixedVersions.Count > 0);
                    return true;
                case "reachable":
                    error = "'reachable' is not available yet: reachability analysis is on the roadmap (v0.2)";
                    return false;
            }

            return TryParseComparison(lower, out term, out error);
        }

        private static bool TryParseComparison(string lower, out Term? term, out string error)
        {
            term = null;
            error = string.Empty;

            int op = lower.IndexOf(">=", StringComparison.Ordinal);
            int opLength = 2;
            bool inclusive = true;

            if (op < 0)
            {
                op = lower.IndexOf('>', StringComparison.Ordinal);
                opLength = 1;
                inclusive = false;
            }

            if (op <= 0)
            {
                error = $"unknown term '{Shown(lower)}' (terms: any, kev, ransomware, direct, fixable, cvss>=N, epss>=P, severity>=LEVEL)";
                return false;
            }

            string name = lower[..op].Trim();
            string value = lower[(op + opLength)..].Trim();

            switch (name)
            {
                case "cvss":
                    if (!TryNumber(value, 0, 10, out double cvss, out error))
                    {
                        error = $"cvss: {error}";
                        return false;
                    }

                    term = new Term(f => f.Signals.Cvss is { } c && Compare(c.BaseScore, cvss, inclusive));
                    return true;

                case "epss":
                    if (!TryNumber(value, 0, 1, out double epss, out error))
                    {
                        error = $"epss: {error}";
                        return false;
                    }

                    term = new Term(f => f.Signals.Epss is { } e && Compare(e.Probability, epss, inclusive));
                    return true;

                case "severity":
                    if (!inclusive)
                    {
                        error = "severity only supports '>=' (for example severity>=high)";
                        return false;
                    }

                    int level = BaselineRanker.SeverityRank(value);

                    if (level == 0)
                    {
                        error = $"severity: unknown level '{Shown(value)}' (low, moderate, medium, high, critical)";
                        return false;
                    }

                    term = new Term(f => BaselineRanker.SeverityRank(f.Severity) >= level);
                    return true;

                default:
                    error = $"unknown term '{Shown(lower)}' (terms: any, kev, ransomware, direct, fixable, cvss>=N, epss>=P, severity>=LEVEL)";
                    return false;
            }
        }

        /// <summary>Text echoed in an error message: control characters removed and length bounded.</summary>
        private static string Shown(string text) => SafeText.Clean(text, 60);

        private static bool Compare(double actual, double threshold, bool inclusive) =>
            inclusive ? actual >= threshold : actual > threshold;

        private static bool TryNumber(string text, double min, double max, out double value, out string error)
        {
            error = string.Empty;

            if (!double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out value)
                || !double.IsFinite(value)
                || value < min
                || value > max)
            {
                error = $"'{Shown(text)}' is not a number between {min.ToString(CultureInfo.InvariantCulture)} and {max.ToString(CultureInfo.InvariantCulture)}";
                return false;
            }

            return true;
        }
    }
}
