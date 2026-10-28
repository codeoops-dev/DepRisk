using Xunit;

namespace DepRisk.Audit.Tests;

public class ArgRedactorTests
{
    [Fact]
    public void Ordinary_arguments_are_kept()
    {
        Assert.Equal(
            new[] { "src", "--format", "json", "--out", "scan.json" },
            ArgRedactor.Redact(["src", "--format", "json", "--out", "scan.json"]).ToArray());
    }

    [Fact]
    public void The_value_after_a_secret_like_option_is_masked()
    {
        Assert.Equal(
            new[] { "--api-key", "***", "--format", "json" },
            ArgRedactor.Redact(["--api-key", "hunter2", "--format", "json"]).ToArray());
    }

    [Fact]
    public void Inline_values_are_masked_too()
    {
        Assert.Equal(
            new[] { "--token=***", "--password=***", "--client-secret=***" },
            ArgRedactor.Redact(["--token=abc", "--password=abc", "--client-secret=abc"]).ToArray());
    }

    [Theory]
    [InlineData("--pubkey")]
    [InlineData("--public-key")]
    [InlineData("--head")]
    public void Public_values_are_not_masked(string option)
    {
        Assert.Equal(new[] { option, "value" }, ArgRedactor.Redact([option, "value"]).ToArray());
    }

    [Fact]
    public void A_secret_option_at_the_end_does_not_fail()
    {
        Assert.Equal(new[] { "--token" }, ArgRedactor.Redact(["--token"]).ToArray());
    }
}
