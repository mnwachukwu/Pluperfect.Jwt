using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Pluperfect.Jwt;

/// <summary>
/// Issues and describes the session token.
/// </summary>
/// <remarks>
/// <para>A signed JWT, symmetric (HMAC-SHA256), issued by a service for itself. There is no
/// shared identity provider — each site in the fleet signs its own — so asymmetric keys would
/// buy nothing and cost a key distribution problem.</para>
///
/// <para>⚠ <strong>The token travels in an HttpOnly cookie, not an <c>Authorization</c>
/// header.</strong> That is the whole security argument for this shape: a credential script
/// cannot read is a credential script cannot exfiltrate, which matters wherever a page renders
/// content somebody else authored. The consequence is that the browser attaches it
/// automatically, so <strong>CSRF protection is not optional</strong> — see
/// <see cref="AntiforgeryFilter"/> and <see cref="OriginFilter"/>.</para>
/// </remarks>
public sealed class JwtIssuer
{
    private static readonly JsonWebTokenHandler Handler = new();

    private readonly PluperfectJwtOptions _options;
    private readonly SymmetricSecurityKey _key;

    /// <summary>Creates an issuer from validated options.</summary>
    /// <param name="options">The bound <c>Jwt</c> section.</param>
    /// <exception cref="InvalidOperationException">
    /// The signing key is absent or shorter than <see cref="PluperfectJwtOptions.MinimumKeyBytes"/>.
    /// </exception>
    public JwtIssuer(IOptions<PluperfectJwtOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options.Value;

        if (string.IsNullOrWhiteSpace(_options.SigningKey))
        {
            // Named precisely, including the environment-variable spelling, because this message
            // is what somebody reads at three in the morning when a deploy will not start.
            throw new InvalidOperationException(
                "Jwt:SigningKey is not configured. Set it as the Jwt__SigningKey environment "
                + $"variable to a random value of at least {PluperfectJwtOptions.MinimumKeyBytes} "
                + "bytes. Pass allowDevelopmentKey: true to AddPluperfectJwt to substitute a "
                + "derived throwaway key, which is honored only where the application allows it.");
        }

        var bytes = Encoding.UTF8.GetBytes(_options.SigningKey);

        // Checked here rather than left to the first login. A short key throws inside the handler
        // at issue time, which surfaces as a 500 on sign-in long after the deploy that caused it.
        if (bytes.Length < PluperfectJwtOptions.MinimumKeyBytes)
        {
            throw new InvalidOperationException(
                $"Jwt:SigningKey is {bytes.Length} bytes; HMAC-SHA256 needs at least "
                + $"{PluperfectJwtOptions.MinimumKeyBytes}.");
        }

        _key = new SymmetricSecurityKey(bytes);
    }

    /// <summary>Signs a token carrying exactly the claims it is given.</summary>
    /// <param name="claims">The claims to embed. Written verbatim; nothing is added.</param>
    /// <param name="expires">When the token stops being valid.</param>
    /// <returns>The compact serialized JWT.</returns>
    public string Issue(IEnumerable<Claim> claims, DateTimeOffset expires) =>
        Handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _options.Issuer,
            Audience = _options.Issuer,
            Subject = new ClaimsIdentity(claims),
            Expires = expires.UtcDateTime,
            SigningCredentials = new SigningCredentials(_key, SecurityAlgorithms.HmacSha256),
        });

    /// <summary>
    /// What the handler checks on the way in.
    /// </summary>
    /// <remarks>
    /// <para>⚠ <c>NameClaimType</c> is set explicitly, and it matters beyond tidiness: a rate
    /// limiter that partitions on <c>User.Identity.Name</c> silently drops every signed-in caller
    /// into the shared by-address bucket if this is left at the default.</para>
    ///
    /// <para>⚠ <c>ClockSkew</c> defaults to five minutes, which quietly extends every expiry.
    /// Thirty seconds is enough for two machines that both run NTP, and here the issuer and the
    /// validator are the same process anyway.</para>
    /// </remarks>
    /// <returns>Validation parameters matching what <see cref="Issue"/> produces.</returns>
    public TokenValidationParameters ValidationParameters() => new()
    {
        ValidateIssuer = true,
        ValidIssuer = _options.Issuer,
        ValidateAudience = true,
        ValidAudience = _options.Issuer,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = _key,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromSeconds(30),

        // Only HMAC-SHA256 is ever issued here. Naming it refuses a token that asks to be
        // validated some other way, which is the shape of the "alg" confusion attacks.
        ValidAlgorithms = [SecurityAlgorithms.HmacSha256],

        NameClaimType = ClaimTypes.Name,
        RoleClaimType = ClaimTypes.Role,
    };
}
