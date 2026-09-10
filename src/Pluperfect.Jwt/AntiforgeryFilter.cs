using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Pluperfect.Jwt;

/// <summary>
/// Opts an endpoint out of antiforgery validation.
/// </summary>
/// <remarks>
/// ⚠ Health checks and similar unauthenticated probes only. Login, register and password reset
/// deliberately do not carry this — those are precisely the endpoints worth protecting.
/// </remarks>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public sealed class SkipAntiforgeryAttribute : Attribute;

/// <summary>
/// Validates the antiforgery token on every state-changing request.
/// </summary>
/// <remarks>
/// <para>Written out rather than using <c>AutoValidateAntiforgeryTokenAttribute</c>, whose filter
/// is only registered by <c>AddControllersWithViews()</c> — pulling in the whole Razor view stack
/// to get one filter is a poor trade for a JSON API. This also keeps the exemption list explicit
/// rather than scattered across attributes.</para>
///
/// <para>The token is cookie-to-header: the antiforgery cookie stays HttpOnly and the request
/// token is handed to the client in a response body, to be echoed as <c>X-CSRF-TOKEN</c>. A token
/// the page could read from a cookie would protect nothing, since anything that can read a cookie
/// can also send it.</para>
/// </remarks>
/// <param name="antiforgery">The framework's antiforgery service.</param>
/// <param name="tokenEndpoint">
/// Where a client fetches a token, named in the failure response so the fix is discoverable from
/// the error alone.
/// </param>
public sealed class AntiforgeryFilter(IAntiforgery antiforgery, string tokenEndpoint)
    : IAsyncAuthorizationFilter
{
    private static readonly string[] SafeMethods = ["GET", "HEAD", "OPTIONS", "TRACE"];

    /// <summary>Validates the token before authorization completes.</summary>
    /// <param name="context">The request being authorized.</param>
    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (SafeMethods.Contains(context.HttpContext.Request.Method, StringComparer.OrdinalIgnoreCase))
        {
            return;
        }

        if (context.ActionDescriptor.EndpointMetadata.OfType<SkipAntiforgeryAttribute>().Any())
        {
            return;
        }

        try
        {
            await antiforgery.ValidateRequestAsync(context.HttpContext).ConfigureAwait(false);
        }
        catch (AntiforgeryValidationException)
        {
            // 400, not 403: the request is malformed rather than forbidden, and the client's fix
            // is to fetch a token, not to log in again.
            context.Result = new ObjectResult(new ProblemDetails
            {
                Status = StatusCodes.Status400BadRequest,
                Title = "Missing or invalid CSRF token.",
                Detail = $"Fetch a token from {tokenEndpoint} and send it as the X-CSRF-TOKEN header.",
            })
            {
                StatusCode = StatusCodes.Status400BadRequest,
            };
        }
    }
}
