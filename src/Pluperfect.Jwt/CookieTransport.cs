using Microsoft.AspNetCore.Http;

namespace Pluperfect.Jwt;

/// <summary>
/// How the tokens are written to and cleared from cookies.
/// </summary>
/// <remarks>
/// <para>⚠ Whether the origin is secure is a <em>parameter</em> everywhere in this type, never
/// something read from the host environment. A library that inspects its host behaves differently
/// depending on who hosts it; the caller states the policy and this decides nothing about where
/// it is running.</para>
///
/// <para>The <c>__Host-</c> prefix is defined by browsers as "Secure, Path=/, no Domain", so it
/// is not decorative — a <c>__Host-</c> cookie without <c>Secure</c> is rejected outright. Host-only
/// is also strictly narrower than a parent-domain cookie, and a subdomain is same-<em>site</em>
/// with its parent, so <c>SameSite=Lax</c> is still sent between <c>example.com</c> and
/// <c>api.example.com</c>.</para>
/// </remarks>
public static class CookieTransport
{
    /// <summary>The prefix browsers enforce as "Secure, Path=/, no Domain".</summary>
    public const string HostPrefix = "__Host-";

    /// <summary>The cookie name to use for this origin.</summary>
    /// <param name="configuredName">The name from options, with or without the prefix.</param>
    /// <param name="secureOrigin">
    /// Whether cookies are served over HTTPS. Pass <c>!builder.Environment.IsDevelopment()</c>, or
    /// whatever else states the policy. False drops the prefix, because a plain-HTTP origin cannot
    /// carry one.
    /// </param>
    /// <returns>The name to read and write.</returns>
    public static string NameFor(string configuredName, bool secureOrigin)
    {
        ArgumentNullException.ThrowIfNull(configuredName);

        var bare = configuredName.Replace(HostPrefix, "", StringComparison.Ordinal);

        return secureOrigin ? HostPrefix + bare : bare;
    }

    /// <summary>Cookie attributes for the access token.</summary>
    /// <param name="secureOrigin">Whether cookies are served over HTTPS.</param>
    /// <param name="expires">
    /// When the browser should discard it, or null for a session cookie. Null is the right answer
    /// for an access token whatever "remember me" says: it is worthless past its own lifetime, and
    /// the refresh token is what makes a session persist.
    /// </param>
    /// <returns>Attributes to pass to <c>Response.Cookies.Append</c>.</returns>
    public static CookieOptions Access(bool secureOrigin, DateTimeOffset? expires = null) => new()
    {
        HttpOnly = true,
        Secure = secureOrigin,
        SameSite = SameSiteMode.Lax,
        Path = "/",
        Expires = expires,
    };

    /// <summary>Cookie attributes for the refresh token.</summary>
    /// <remarks>
    /// ⚠ <paramref name="path"/> scopes the one credential worth stealing away from every request
    /// that has no use for it — and it must be identical on the cookie that clears it. A
    /// <c>Set-Cookie</c> whose <c>Path</c> differs creates a second cookie rather than removing the
    /// first, and the browser goes on sending the original: a sign-out that appears to work and
    /// does not.
    /// </remarks>
    /// <param name="secureOrigin">Whether cookies are served over HTTPS.</param>
    /// <param name="path">The route that redeems it, from <see cref="PluperfectJwtOptions.RefreshCookiePath"/>.</param>
    /// <param name="expires">
    /// When the browser should discard it, or null for a session cookie. Omitting it entirely is
    /// what makes a browser treat the login as non-persistent.
    /// </param>
    /// <returns>Attributes to pass to <c>Response.Cookies.Append</c>.</returns>
    public static CookieOptions Refresh(bool secureOrigin, string path, DateTimeOffset? expires = null) => new()
    {
        HttpOnly = true,
        Secure = secureOrigin,
        SameSite = SameSiteMode.Lax,
        Path = path,
        Expires = expires,
    };

    /// <summary>
    /// Attributes that clear a cookie of the same shape.
    /// </summary>
    /// <remarks>
    /// The expiry is in the past and every other attribute matches, because a browser removes a
    /// cookie only when name, <c>Path</c> and <c>Domain</c> all agree.
    /// </remarks>
    /// <param name="secureOrigin">Whether cookies are served over HTTPS.</param>
    /// <param name="path">The same path the cookie was written with.</param>
    /// <returns>Attributes that delete rather than add.</returns>
    public static CookieOptions Clearing(bool secureOrigin, string path) => new()
    {
        HttpOnly = true,
        Secure = secureOrigin,
        SameSite = SameSiteMode.Lax,
        Path = path,
        Expires = DateTimeOffset.UnixEpoch,
    };
}
