using System.ComponentModel.DataAnnotations;

namespace Pluperfect.Jwt;

/// <summary>
/// Everything the session needs to be configured with.
/// </summary>
/// <remarks>
/// Bound from the <c>Jwt</c> configuration section. Every consuming service supplies its own
/// values; nothing here has a default that would be wrong to ship.
/// </remarks>
public sealed class PluperfectJwtOptions
{
    /// <summary>The configuration section these bind from.</summary>
    public const string Section = "Jwt";

    /// <summary>HMAC-SHA256 needs 256 bits; anything shorter is refused by the handler.</summary>
    public const int MinimumKeyBytes = 32;

    /// <summary>
    /// SECRET. The HMAC-SHA256 key the session token is signed with.
    /// </summary>
    /// <remarks>
    /// <para>⚠ At least <see cref="MinimumKeyBytes"/> bytes. A shorter key is rejected by the
    /// handler at issue time, so without validation here a too-short value fails on the first
    /// login rather than at startup.</para>
    ///
    /// <para>⚠ Changing it signs everybody out. Rotating gracefully would mean accepting two keys
    /// at once, which this does not do, so treat it as a value you set and leave.</para>
    ///
    /// <para>Leave empty only when the caller passes <c>allowDevelopmentKey: true</c> to
    /// <see cref="ServiceCollectionExtensions.AddPluperfectJwt"/>, in which case a key derived
    /// from <see cref="Issuer"/> is substituted. Anywhere else, empty is a startup failure.</para>
    /// </remarks>
    public string SigningKey { get; set; } = "";

    /// <summary>
    /// Both the issuer and the audience: a service signs tokens for itself.
    /// </summary>
    /// <remarks>
    /// Each site in the fleet issues its own tokens, so there is no shared authority to name.
    /// Validating both anyway costs nothing and means a token minted for one site cannot be
    /// replayed at another even if the two ever end up sharing a signing key by accident.
    /// </remarks>
    [Required]
    public string Issuer { get; set; } = "";

    /// <summary>
    /// How long an access token is good for.
    /// </summary>
    /// <remarks>
    /// ⚠ This is the revocation window. An access token cannot be withdrawn once signed — there
    /// is no per-request database check, which is the point of a token — so a ban, a demotion or
    /// a sign-out elsewhere takes effect when the current one expires and the refresh re-reads
    /// the account.
    /// </remarks>
    [Range(1, 240)]
    public int AccessTokenMinutes { get; set; } = 15;

    /// <summary>
    /// How long a refresh token is good for. The true session length.
    /// </summary>
    /// <remarks>
    /// Rotation resets it on every use, so an active session never expires; this is how long a
    /// session may sit idle before it has to be re-established with a password.
    /// </remarks>
    [Range(1, 365)]
    public int RefreshTokenDays { get; set; } = 7;

    /// <summary>
    /// How long a dead refresh row is kept before <see cref="IRefreshTokenStore.DeleteDeadAsync"/>
    /// may remove it.
    /// </summary>
    /// <remarks>
    /// A replay arriving inside this window is still recognised as a replay rather than as an
    /// unknown token, which is the difference between detecting theft and shrugging at it.
    /// </remarks>
    [Range(1, 365)]
    public int RevokedTokenGraceDays { get; set; } = 30;

    /// <summary>The cookie carrying the access token.</summary>
    /// <remarks>
    /// The <c>__Host-</c> prefix is applied by <see cref="CookieTransport"/> rather than written
    /// here, because it is only valid on a secure origin — see that type.
    /// </remarks>
    [Required]
    public string AccessCookieName { get; set; } = "sid";

    /// <summary>The cookie carrying the refresh token.</summary>
    [Required]
    public string RefreshCookieName { get; set; } = "rt";

    /// <summary>
    /// The path the refresh cookie is scoped to.
    /// </summary>
    /// <remarks>
    /// ⚠ Scoped deliberately, so the one credential worth stealing is absent from every request
    /// that has no use for it. It must match the route that actually redeems it, and it must be
    /// identical on the <c>Set-Cookie</c> that clears it: a clearing cookie whose <c>Path</c>
    /// differs creates a second cookie instead of removing the first, and the browser goes on
    /// sending the original — a sign-out that appears to work and does not.
    /// </remarks>
    [Required]
    public string RefreshCookiePath { get; set; } = "/auth";
}
