using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Pluperfect.Jwt;

/// <summary>Registers this library with an application's container.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>The authentication scheme this library registers.</summary>
    public const string Scheme = "PluperfectJwt";

    /// <summary>
    /// Adds cookie-carried JWT authentication.
    /// </summary>
    /// <remarks>
    /// <para>Registers <see cref="JwtIssuer"/> and a <c>JwtBearer</c> handler that reads the token
    /// from a cookie rather than from an <c>Authorization</c> header. It does <em>not</em> register
    /// an <see cref="IRefreshTokenStore"/>: that needs a database, and every consumer already has
    /// one this library should not choose.</para>
    ///
    /// <para><paramref name="allowDevelopmentKey"/> and <paramref name="secureOrigin"/> are
    /// parameters rather than environment checks inside this library, because a library that reads
    /// the host environment is a library that behaves differently depending on who hosts it. The
    /// caller states the policy; this decides nothing about where it is running. Both default to
    /// the safe answer, so forgetting them fails closed.</para>
    /// </remarks>
    /// <param name="services">The container.</param>
    /// <param name="configuration">Configuration carrying the <c>Jwt</c> section.</param>
    /// <param name="allowDevelopmentKey">
    /// Whether an absent <c>Jwt:SigningKey</c> may be replaced by a key derived from the issuer.
    /// Pass <c>builder.Environment.IsDevelopment()</c>. Defaults to false.
    /// </param>
    /// <param name="secureOrigin">
    /// Whether cookies are served over HTTPS, which decides the <c>__Host-</c> prefix and the
    /// <c>Secure</c> attribute. Pass <c>!builder.Environment.IsDevelopment()</c>. Defaults to true.
    /// </param>
    /// <returns>The container, for chaining.</returns>
    public static IServiceCollection AddPluperfectJwt(
        this IServiceCollection services,
        IConfiguration configuration,
        bool allowDevelopmentKey = false,
        bool secureOrigin = true)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        var section = configuration.GetSection(PluperfectJwtOptions.Section);

        services.AddOptions<PluperfectJwtOptions>()
            .Bind(section)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        if (allowDevelopmentKey)
        {
            services.PostConfigure<PluperfectJwtOptions>(options =>
            {
                if (string.IsNullOrWhiteSpace(options.SigningKey))
                {
                    options.SigningKey = DerivedDevelopmentKey(options.Issuer);
                }
            });
        }

        services.TryAddSingleton<JwtIssuer>();

        var bound = section.Get<PluperfectJwtOptions>() ?? new PluperfectJwtOptions();
        var cookieName = CookieTransport.NameFor(bound.AccessCookieName, secureOrigin);

        services
            .AddAuthentication(Scheme)
            .AddJwtBearer(Scheme, options =>
            {
                /*
                 * ⚠ Claim types must arrive exactly as they were written.
                 *
                 * With inbound mapping on, the handler rewrites short JWT names into the long
                 * WS-* URIs — so a claim can arrive under a type the reading code never asks for.
                 * User.FindFirstValue then returns null and authorization degrades to "not signed
                 * in", silently and with nothing logged.
                 */
                options.MapInboundClaims = false;

                // Real parameters are supplied per-request in OnMessageReceived, where JwtIssuer
                // can be resolved. Configuration read during service registration is read before
                // the final configuration sources are in place, and binds whatever happens to be
                // there at that moment.
                options.TokenValidationParameters = new()
                {
                    ValidateIssuerSigningKey = false,
                    SignatureValidator = static (token, _) => new JsonWebToken(token),
                };

                options.Events = new JwtBearerEvents
                {
                    OnMessageReceived = context =>
                    {
                        var token = context.Request.Cookies[cookieName];

                        /*
                         * ⚠ NoResult(), not `Token = null`.
                         *
                         * An unset Token is the handler's signal to go looking for one itself, and
                         * what it looks at is the Authorization header. Leaving it null therefore
                         * does not mean "no credential" — it means "fall back to bearer", so a
                         * token lifted out of a browser could be replayed by any client at all.
                         * NoResult() ends the handler instead: no cookie, not signed in.
                         */
                        if (string.IsNullOrEmpty(token))
                        {
                            context.NoResult();
                            return Task.CompletedTask;
                        }

                        context.Token = token;

                        var issuer = context.HttpContext.RequestServices.GetRequiredService<JwtIssuer>();
                        context.Options.TokenValidationParameters = issuer.ValidationParameters();

                        return Task.CompletedTask;
                    },

                    // A JSON API answers with a status code. A redirect here reaches the SPA as a
                    // cross-origin navigation and surfaces as an opaque CORS error rather than as
                    // "you are signed out", which is unreadable from the browser console.
                    OnChallenge = context =>
                    {
                        context.HandleResponse();
                        context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                        return Task.CompletedTask;
                    },

                    OnForbidden = context =>
                    {
                        context.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                        return Task.CompletedTask;
                    },
                };
            });

        return services;
    }

    /// <summary>
    /// A stable throwaway signing key, derived from the issuer.
    /// </summary>
    /// <remarks>
    /// <para>Derived rather than constant, so two services running side by side in development do
    /// not accept each other's tokens — and so this library ships no key that every consumer would
    /// share. Derived rather than random, so restarting during development does not sign a
    /// developer out mid-task.</para>
    ///
    /// <para>⚠ Reachable only when the caller passes <c>allowDevelopmentKey: true</c>. The gate is
    /// the caller's stated policy, not the value being absent: a default that is merely "used when
    /// unset" reaches production the first time somebody copies a settings file.</para>
    /// </remarks>
    private static string DerivedDevelopmentKey(string issuer) =>
        Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes("pluperfect-jwt-development-only:" + issuer)));
}
