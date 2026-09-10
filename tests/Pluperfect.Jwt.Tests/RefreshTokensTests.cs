using NUnit.Framework;
using Shouldly;

namespace Pluperfect.Jwt.Tests;

[TestFixture]
public sealed class RefreshTokensTests
{
    [Test]
    public void Creates_a_distinct_token_every_time()
    {
        var tokens = Enumerable.Range(0, 200).Select(_ => RefreshTokens.Create()).ToList();

        tokens.Distinct(StringComparer.Ordinal).Count().ShouldBe(tokens.Count);
    }

    [Test]
    public void Creates_tokens_that_survive_a_Set_Cookie_header_unchanged()
    {
        // Base64url, not base64: '+', '/' and '=' are either reserved in a cookie value or invite
        // quoting, and a cookie that round-trips differently than it was written is a session
        // that fails on some clients and not others.
        foreach (var token in Enumerable.Range(0, 200).Select(_ => RefreshTokens.Create()))
        {
            token.ShouldNotContain("+");
            token.ShouldNotContain("/");
            token.ShouldNotContain("=");
        }
    }

    [Test]
    public void Hashes_to_lower_case_hex_of_a_fixed_width()
    {
        // The storage column is sized for exactly this.
        var hash = RefreshTokens.Hash(RefreshTokens.Create());

        hash.Length.ShouldBe(64);
        hash.ShouldBe(hash.ToLowerInvariant());
        hash.ShouldAllBe(c => Uri.IsHexDigit(c));
    }

    [Test]
    public void Hashes_the_same_token_to_the_same_value()
    {
        // Lookup depends on it: the store finds a row by hashing what the client presented.
        var token = RefreshTokens.Create();

        RefreshTokens.Hash(token).ShouldBe(RefreshTokens.Hash(token));
    }

    [Test]
    public void Hashes_different_tokens_to_different_values()
    {
        RefreshTokens.Hash(RefreshTokens.Create())
            .ShouldNotBe(RefreshTokens.Hash(RefreshTokens.Create()));
    }

    [Test]
    public void Does_not_expose_the_raw_token_in_its_hash()
    {
        // A reader of the table must not be able to present what they find there.
        var token = RefreshTokens.Create();

        RefreshTokens.Hash(token).ShouldNotContain(token);
    }
}
