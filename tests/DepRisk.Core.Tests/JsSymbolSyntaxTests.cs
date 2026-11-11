using DepRisk.Core.Reach;
using Xunit;

namespace DepRisk.Core.Tests;

public sealed class JsSymbolSyntaxTests
{
    [Theory]
    [InlineData("lodash")]
    [InlineData("@scope/pkg")]
    [InlineData("lodash/fp")]
    [InlineData("a.b_c-d")]
    public void Package_specifiers_of_npm_are_valid(string package) => Assert.True(SymbolSyntax.IsValidJsPackage(package));

    [Theory]
    [InlineData("")]
    [InlineData(".")]
    [InlineData("./local")]
    [InlineData("../up")]
    [InlineData("/abs")]
    [InlineData("a//b")]
    [InlineData("a/")]
    [InlineData("has space")]
    [InlineData("bad::name")]
    public void Relative_absolute_and_malformed_specifiers_are_not_packages(string package) => Assert.False(SymbolSyntax.IsValidJsPackage(package));

    [Fact]
    public void A_package_name_has_a_length_limit()
    {
        Assert.True(SymbolSyntax.IsValidJsPackage(new string('a', 214)));
        Assert.False(SymbolSyntax.IsValidJsPackage(new string('a', 215)));
        Assert.False(SymbolSyntax.IsValidJsPackage(null));
    }

    [Theory]
    [InlineData("template")]
    [InlineData("Parser.parse")]
    [InlineData("Parser.*")]
    [InlineData("default")]
    [InlineData("default.x")]
    [InlineData("*")]
    [InlineData("$el.go_2")]
    public void Member_paths_are_identifiers_with_an_optional_wildcard_at_the_end(string path) => Assert.True(SymbolSyntax.IsValidJsPath(path));

    [Theory]
    [InlineData("")]
    [InlineData(".")]
    [InlineData("a..b")]
    [InlineData("*.a")]
    [InlineData("a.*.b")]
    [InlineData("1a")]
    [InlineData("a-b")]
    [InlineData("a b")]
    [InlineData("a.")]
    [InlineData(".*")]
    public void Anything_else_is_not_a_member_path(string path) => Assert.False(SymbolSyntax.IsValidJsPath(path));

    [Fact]
    public void A_relative_symbol_is_prefixed_with_the_package_of_its_entry()
    {
        Assert.Equal("lodash::template", SymbolSyntax.ComposeJs("lodash", "template"));
        Assert.Equal("@scope/pkg::Parser.*", SymbolSyntax.ComposeJs("@scope/pkg", "Parser.*"));
        Assert.Equal("pkg::*", SymbolSyntax.ComposeJs("pkg", "*"));
    }

    [Fact]
    public void A_full_symbol_must_name_the_package_of_its_entry_or_a_subpath_of_it()
    {
        Assert.Equal("lodash::template", SymbolSyntax.ComposeJs("lodash", "lodash::template"));
        Assert.Equal("lodash/fp::map", SymbolSyntax.ComposeJs("lodash", "lodash/fp::map"));

        // Another package, or a package whose name merely starts the same way, is not this package.
        Assert.Null(SymbolSyntax.ComposeJs("lodash", "underscore::template"));
        Assert.Null(SymbolSyntax.ComposeJs("lodash", "lodash-es::template"));
        Assert.Null(SymbolSyntax.ComposeJs("@scope/pkg", "@scope/other::x"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("1a")]
    [InlineData("a b")]
    [InlineData("lodash::")]
    [InlineData("lodash::a..b")]
    [InlineData("A.B.C::")]
    public void Composition_refuses_malformed_symbols(string symbol) => Assert.Null(SymbolSyntax.ComposeJs("lodash", symbol));

    [Fact]
    public void Composition_refuses_a_bad_package_a_null_symbol_and_an_overlong_one()
    {
        Assert.Null(SymbolSyntax.ComposeJs("../x", "a"));
        Assert.Null(SymbolSyntax.ComposeJs("lodash", null));
        Assert.Null(SymbolSyntax.ComposeJs("lodash", new string('a', 600)));
    }

    [Theory]
    [InlineData("src/app.js::handler", true)]
    [InlineData("src/app.ts::Svc.run", true)]
    [InlineData("src/app.js::*", true)]
    [InlineData("a::b", true)]
    [InlineData("no-separator", false)]
    [InlineData("::name", false)]
    [InlineData("file.js::", false)]
    [InlineData("", false)]
    [InlineData("file\u001b.js::x", false)]
    public void Function_ids_have_a_file_and_a_name(string id, bool valid) => Assert.Equal(valid, SymbolSyntax.IsValidJsFunctionId(id));

    [Fact]
    public void The_languages_are_known_by_name()
    {
        Assert.True(SymbolLanguages.IsKnown("csharp"));
        Assert.True(SymbolLanguages.IsKnown("javascript"));
        Assert.False(SymbolLanguages.IsKnown("typescript"));
        Assert.False(SymbolLanguages.IsKnown(null));
    }
}
