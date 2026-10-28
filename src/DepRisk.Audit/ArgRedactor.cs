namespace DepRisk.Audit;

/// <summary>Masks the values of options that look like secrets before arguments are written to the audit log.</summary>
public static class ArgRedactor
{
    public const string Mask = "***";

    private static readonly HashSet<string> ExactNames = new(StringComparer.Ordinal)
    {
        "key", "apikey", "api-key", "token", "secret", "password", "passwd", "private-key", "privatekey",
    };

    private static readonly string[] SuffixNames = ["-token", "-secret", "-password", "-passwd"];

    public static IReadOnlyList<string> Redact(IEnumerable<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);

        List<string> result = [];
        bool maskNext = false;

        foreach (string arg in args)
        {
            if (maskNext)
            {
                result.Add(Mask);
                maskNext = false;
                continue;
            }

            if (arg.StartsWith('-'))
            {
                int equals = arg.IndexOf('=', StringComparison.Ordinal);
                string name = equals >= 0 ? arg[..equals] : arg;

                if (IsSensitive(name))
                {
                    if (equals >= 0)
                    {
                        result.Add(name + "=" + Mask);
                    }
                    else
                    {
                        result.Add(arg);
                        maskNext = true;
                    }

                    continue;
                }
            }

            result.Add(arg);
        }

        return result;
    }

    private static bool IsSensitive(string optionName)
    {
        string name = optionName.TrimStart('-').ToLowerInvariant();

        if (ExactNames.Contains(name))
        {
            return true;
        }

        if (SuffixNames.Any(name.EndsWith))
        {
            return true;
        }

        // "--signing-key" is a secret, "--pubkey" and "--public-key" are not.
        return name.EndsWith("-key", StringComparison.Ordinal) && !name.StartsWith("pub", StringComparison.Ordinal);
    }
}
