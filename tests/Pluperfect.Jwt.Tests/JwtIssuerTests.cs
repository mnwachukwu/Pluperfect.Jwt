using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NUnit.Framework;
using Shouldly;

namespace Pluperfect.Jwt.Tests;

[TestFixture]
public sealed class JwtIssuerTests
{
    private const string GoodKey = "a-signing-key-of-at-least-thirty-two-bytes";

    private static JwtIssuer IssuerWith(string key = GoodKey, string issuer = "example.com") =>
        new(Options.Create(new PluperfectJwtOptions { SigningKey = key, Issuer = issuer }));

    [Test]
    public void Refuses_a_missing_signing_key()
    {
        var act = () => IssuerWith(key: "");

        // The message is the whole point: it names the setting and the environment-variable
        // spelling, because it is read by somebody whose deploy will not start.
        act.ShouldThrow<InvalidOperationException>()
            .Message.ShouldContain("Jwt__SigningKey");
    }

    [Test]
    public void Refuses_a_key_shorter_than_HMAC_SHA256_requires()
    {
        var act = () => IssuerWith(key: "too-short");

        act.ShouldThrow<InvalidOperationException>()
            .Message.ShouldContain("32");
    }

    [Test]
    public async Task Issues_a_token_that_validates_against_its_own_parameters()
    {
        var issuer = IssuerWith();

        var token = issuer.Issue(
            [new Claim(ClaimTypes.NameIdentifier, "user-1")],
            DateTimeOffset.UtcNow.AddMinutes(15));

        var result = await new JsonWebTokenHandler()
            .ValidateTokenAsync(token, issuer.ValidationParameters());

        result.IsValid.ShouldBeTrue();
    }

    [Test]
    public async Task Round_trips_claims_under_the_type_they_were_written_with()
    {
        // Claim types surviving verbatim is what MapInboundClaims = false buys. If the handler
        // rewrites them into the long WS-* URIs, FindFirstValue returns null in the consuming
        // application and authorization silently degrades to "not signed in".
        var issuer = IssuerWith();

        var token = issuer.Issue(
            [new Claim("site_privileged", "true"), new Claim(ClaimTypes.Name, "matt")],
            DateTimeOffset.UtcNow.AddMinutes(15));

        var handler = new JsonWebTokenHandler();
        var result = await handler.ValidateTokenAsync(token, issuer.ValidationParameters());

        result.IsValid.ShouldBeTrue();
        result.ClaimsIdentity.FindFirst("site_privileged")?.Value.ShouldBe("true");
    }

    [Test]
    public async Task Rejects_a_token_signed_for_a_different_issuer()
    {
        // Each site signs its own. Validating issuer and audience means a token minted for one
        // cannot be replayed at another even if the two ever share a key by accident.
        var minted = IssuerWith(issuer: "pokestory.net");
        var reader = IssuerWith(issuer: "forty.life");

        var token = minted.Issue([new Claim(ClaimTypes.Name, "x")], DateTimeOffset.UtcNow.AddMinutes(5));

        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, reader.ValidationParameters());

        result.IsValid.ShouldBeFalse();
    }

    [Test]
    public async Task Rejects_an_expired_token_without_the_default_clock_skew()
    {
        // The handler's default skew is five minutes, which quietly extends every expiry. Two
        // minutes past expiry must be rejected, which it would not be at the default.
        var issuer = IssuerWith();

        var token = issuer.Issue(
            [new Claim(ClaimTypes.Name, "x")],
            DateTimeOffset.UtcNow.AddMinutes(-2));

        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, issuer.ValidationParameters());

        result.IsValid.ShouldBeFalse();
    }

    [Test]
    public void Accepts_only_HMAC_SHA256()
    {
        // Naming the algorithm refuses a token asking to be validated some other way, which is
        // the shape of the "alg" confusion attacks.
        IssuerWith().ValidationParameters().ValidAlgorithms
            .ShouldBe([SecurityAlgorithms.HmacSha256]);
    }

    [Test]
    public void Names_the_claim_types_a_rate_limiter_partitions_on()
    {
        // Left at the default, User.Identity.Name is null and every signed-in caller drops into
        // the shared by-address bucket.
        var parameters = IssuerWith().ValidationParameters();

        parameters.NameClaimType.ShouldBe(ClaimTypes.Name);
        parameters.RoleClaimType.ShouldBe(ClaimTypes.Role);
    }
}
