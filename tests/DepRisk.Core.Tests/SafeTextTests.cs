using Xunit;

namespace DepRisk.Core.Tests;

public class SafeTextTests
{
    [Fact]
    public void Control_characters_become_spaces_and_text_is_kept()
    {
        string cleaned = SafeText.Clean("a\u001b[31mred\u0007\nb\tc\u007Fd\u0085e\u2028f", 100);

        // Ordinal checks on purpose: xunit's string overloads ignore control characters.
        Assert.False(cleaned.Any(c => c < 0x20 || (c >= '\u007F' && c <= '\u009F') || c == '\u2028'));
        Assert.Contains("red", cleaned);
        Assert.Equal("a [31mred  b c d e f", cleaned);
    }

    [Fact]
    public void Long_text_is_cut_with_an_ellipsis()
    {
        string cleaned = SafeText.Clean(new string('x', 50), 10);

        Assert.Equal(new string('x', 10) + "…", cleaned);
    }

    [Fact]
    public void Text_at_exactly_the_limit_is_not_cut()
    {
        Assert.Equal(new string('x', 10), SafeText.Clean(new string('x', 10), 10));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Empty_input_gives_an_empty_string(string? input)
    {
        Assert.Equal(string.Empty, SafeText.Clean(input, 10));
    }

    [Fact]
    public void Non_ascii_text_and_surrogate_pairs_are_kept()
    {
        Assert.Equal("پروژه 😀 é", SafeText.Clean("پروژه 😀 é", 50));
    }
}
