using Microsoft.AspNetCore.Http;
using NUnit.Framework;
using Shouldly;

namespace Pluperfect.Jwt.Tests;

[TestFixture]
public sealed class CookieTransportTests
{
    [Test]
    public void Applies_the_host_prefix_on_a_secure_origin()
    {
        CookieTransport.NameFor("sid", secureOrigin: true).ShouldBe("__Host-sid");
    }

    [Test]
    public void Drops_the_host_prefix_on_a_plain_origin()
    {
        // A __Host- cookie without Secure is rejected outright by the browser, so development
        // over plain HTTP has to go without it.
        CookieTransport.NameFor("sid", secureOrigin: false).ShouldBe("sid");
    }

    [Test]
    public void Does_not_double_the_prefix_when_it_is_already_configured()
    {
        CookieTransport.NameFor("__Host-sid", secureOrigin: true).ShouldBe("__Host-sid");
        CookieTransport.NameFor("__Host-sid", secureOrigin: false).ShouldBe("sid");
    }

    [Test]
    public void Keeps_the_access_cookie_unreadable_from_script()
    {
        // The entire security argument for carrying a JWT in a cookie: a credential script
        // cannot read is one script cannot exfiltrate.
        var cookie = CookieTransport.Access(secureOrigin: true);

        cookie.HttpOnly.ShouldBeTrue();
        cookie.Secure.ShouldBeTrue();
        cookie.SameSite.ShouldBe(SameSiteMode.Lax);
        cookie.Path.ShouldBe("/");
    }

    [Test]
    public void Defaults_the_access_cookie_to_a_session_cookie()
    {
        // Worthless past its own lifetime, so persisting it buys nothing. The refresh token is
        // what makes a session outlive the window.
        CookieTransport.Access(secureOrigin: true).Expires.ShouldBeNull();
    }

    [Test]
    public void Scopes_the_refresh_cookie_to_the_route_that_redeems_it()
    {
        // The one credential worth stealing is absent from every request with no use for it.
        var cookie = CookieTransport.Refresh(secureOrigin: true, path: "/auth");

        cookie.Path.ShouldBe("/auth");
        cookie.HttpOnly.ShouldBeTrue();
    }

    [Test]
    public void Clears_with_attributes_matching_what_was_written()
    {
        // A Set-Cookie whose Path differs creates a second cookie rather than removing the first,
        // and the browser goes on sending the original: a sign-out that appears to work and does
        // not.
        var written = CookieTransport.Refresh(secureOrigin: true, path: "/auth");
        var clearing = CookieTransport.Clearing(secureOrigin: true, path: "/auth");

        clearing.Path.ShouldBe(written.Path);
        clearing.Secure.ShouldBe(written.Secure);
        clearing.SameSite.ShouldBe(written.SameSite);
        clearing.Expires.ShouldNotBeNull();
        clearing.Expires!.Value.ShouldBeLessThan(DateTimeOffset.UtcNow);
    }
}
