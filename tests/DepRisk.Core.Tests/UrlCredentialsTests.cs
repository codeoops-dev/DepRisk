using System.Diagnostics;
using DepRisk.Core;
using Xunit;

namespace DepRisk.Core.Tests;

public class UrlCredentialsTests
{
    [Theory]
    // URL user information is replaced, the rest is kept as written.
    [InlineData("git+https://user:TOKEN123@example.com/org/a.git", "git+https://***@example.com/org/a.git")]
    [InlineData("git+https://user:TOKEN123@example.com/org/b.git#semver:^1", "git+https://***@example.com/org/b.git#semver:^1")]
    [InlineData("https://TOKEN@github.com/org/repo.git", "https://***@github.com/org/repo.git")]
    [InlineData("https://@example.com/x", "https://***@example.com/x")]
    [InlineData("https://user:p%40ss@example.com/x.tgz", "https://***@example.com/x.tgz")]
    [InlineData("https://user:p@ss@example.com/x.tgz", "https://***@example.com/x.tgz")]
    [InlineData("HTTPS://user:pw@Example.com", "HTTPS://***@Example.com")]
    [InlineData("git+ssh://deploy:pw@example.com:org/repo.git", "git+ssh://***@example.com:org/repo.git")]
    [InlineData("https://user:pa?ss@example.com/x", "https://***@example.com/x")]
    [InlineData("https://user:pa#ss@example.com/x", "https://***@example.com/x")]
    // Several URLs in one text, also one inside a query.
    [InlineData("https://a:b@h/x?u=https://c:d@h2/y", "https://***@h/x?u=https://***@h2/y")]
    [InlineData("https://h/x?u=https://c:d@h2/y", "https://h/x?u=https://***@h2/y")]
    // A scheme-less authority before a later "://".
    [InlineData("user:pw@example.com/x?u=http://z", "***@example.com/x?u=http://z")]
    // scp-like specifiers.
    [InlineData("TOKEN@github.com:org/repo.git", "***@github.com:org/repo.git")]
    [InlineData("deploy:pw@example.com:org/repo.git#v1", "***@example.com:org/repo.git#v1")]
    public void Credentials_in_a_url_are_masked(string input, string expected)
    {
        Assert.Equal(expected, UrlCredentials.Mask(input));
    }

    [Theory]
    [InlineData("")]
    [InlineData("^1.2.3")]
    [InlineData(">=1.0.0 <2.0.0 || ^3.1.0-beta.1")]
    [InlineData("[1.0.0, 2.0.0)")]
    [InlineData("1.2.3+build.5")]
    [InlineData("npm:@scope/name@^1.0.0")]
    [InlineData("npm:name@1.2.3")]
    [InlineData("@scope/name")]
    [InlineData("github:user/repo#semver:^1")]
    [InlineData("file:../local")]
    [InlineData("https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz")]
    [InlineData("https://example.com/org/repo.git#abc123")]
    [InlineData("git+ssh://git@github.com/org/repo.git#v1.0.0")]
    [InlineData("git@github.com:org/repo.git")]
    [InlineData("***@example.com/x")]
    [InlineData("https://***@example.com/x")]
    public void Text_without_credentials_is_returned_as_it_was(string input)
    {
        Assert.Equal(input, UrlCredentials.Mask(input));
    }

    [Theory]
    [InlineData("https://user:TOKEN123@example.com/org/a.git")]
    [InlineData("git+https://a:b@h/x?u=https://c:d@h2/y")]
    [InlineData("TOKEN@github.com:org/repo.git")]
    [InlineData("https://@@@h/")]
    [InlineData("://@")]
    [InlineData("a@b@c://d@e@f/@g")]
    [InlineData("git@git@x")]
    public void Masking_twice_is_the_same_as_masking_once(string input)
    {
        string once = UrlCredentials.Mask(input);

        Assert.Equal(once, UrlCredentials.Mask(once));
    }

    [Fact]
    public void Whatever_a_url_parser_reads_as_user_information_does_not_survive()
    {
        string[] users = ["user:pw", "TOKEN", "ghp_AbCdEf0123456789", "a:b:c", "user:p%40ss", "Zq9x", "us.er-1_2~3", "u:p%2Fw"];
        string[] hosts = ["example.com", "EXAMPLE.com", "h", "a.b.c:8080", "[::1]", "192.168.0.1"];
        string[] paths = ["", "/", "/org/repo.git", "/@scope/pkg", "/a?b=c", "/a#frag", "/x@y"];
        string[] schemes = ["http", "https", "git+https", "ssh", "git+ssh", "ftp", "ws"];
        int checkedByParser = 0;

        foreach (string scheme in schemes)
        {
            foreach (string user in users)
            {
                foreach (string host in hosts)
                {
                    foreach (string path in paths)
                    {
                        string text = $"{scheme}://{user}@{host}{path}";

                        // System.Uri only knows some schemes; for the others, the user is known by construction.
                        string readByParser = Uri.TryCreate(text, UriKind.Absolute, out Uri? uri) && uri.UserInfo.Length > 0 ? uri.UserInfo : user;
                        checkedByParser++;

                        string masked = UrlCredentials.Mask(text);

                        Assert.DoesNotContain(readByParser, masked);
                        Assert.DoesNotContain(user, masked);
                        Assert.Contains("***@", masked);
                    }
                }
            }
        }

        Assert.True(checkedByParser > 1000);
    }

    [Fact]
    public void Random_text_never_throws_stays_idempotent_and_never_grows_without_bound()
    {
        const string alphabet = "ab:/\\@?#.%-_ 1:// @@ git";
        Random random = new(20261124);

        for (int i = 0; i < 20000; i++)
        {
            int length = random.Next(0, 60);
            char[] chars = new char[length];

            for (int c = 0; c < length; c++)
            {
                chars[c] = alphabet[random.Next(alphabet.Length)];
            }

            string text = new(chars);
            string masked = UrlCredentials.Mask(text);

            Assert.Equal(masked, UrlCredentials.Mask(masked));

            // Each '@' can cost at most the three characters of the placeholder.
            Assert.True(masked.Length <= text.Length + (3 * text.Count(ch => ch == '@')), text);

            // Nothing in front of an '@' of a "://" authority survives, unless it is the public user.
            int separator = masked.IndexOf("://", StringComparison.Ordinal);

            if (separator >= 0)
            {
                int start = separator + 3;
                int end = masked.IndexOfAny(['/', '\\'], start);
                string authority = masked[start..(end < 0 ? masked.Length : end)];
                int at = authority.LastIndexOf('@');

                if (at >= 0)
                {
                    Assert.True(authority[..at] is "git" or "***", $"{text} -> {masked}");
                }
            }
        }
    }

    [Fact]
    public void The_cost_is_linear_in_the_length_of_the_text()
    {
        string hostile = string.Concat(Enumerable.Repeat("://@a:b@", 200_000));   // 1.6 million characters
        string longAuthority = "https://" + new string('a', 1_000_000) + "@h";
        string manyAt = "https://" + string.Concat(Enumerable.Repeat("@", 1_000_000));

        Stopwatch watch = Stopwatch.StartNew();

        _ = UrlCredentials.Mask(hostile);
        _ = UrlCredentials.Mask(longAuthority);
        _ = UrlCredentials.Mask(manyAt);

        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), $"took {watch.Elapsed}");
    }

    [Fact]
    public void A_null_text_is_a_programming_error()
    {
        Assert.Throws<ArgumentNullException>(() => UrlCredentials.Mask(null!));
    }
}
