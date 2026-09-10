using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Pluperfect.Jwt;

/// <summary>
/// Rejects state-changing requests whose <c>Origin</c> or <c>Referer</c> is not on the allow-list.
/// </summary>
/// <remarks>
/// <para>The second of three CSRF layers, and the one that keeps working when the others do
/// not.</para>
///
/// <list type="number">
/// <item><c>SameSite=Lax</c> already stops cross-site non-GET requests — but it is a browser
/// default, and browsers have changed their defaults before.</item>
/// <item>This filter, which is stateless and does not care what the browser decided.</item>
/// <item>ASP.NET antiforgery, cookie-to-header — see <see cref="AntiforgeryFilter"/>.</item>
/// </list>
///
/// <para>A request carrying neither header is allowed through: those are not browsers, so they are
/// not the thing CSRF protects against, and blocking them would break curl and every health
/// checker. The antiforgery token still applies to them.</para>
/// </remarks>
/// <param name="registry">The permitted origins.</param>
public sealed class OriginFilter(AllowedOriginRegistry registry) : IAsyncActionFilter
{
    private static readonly string[] SafeMethods = ["GET", "HEAD", "OPTIONS", "TRACE"];

    /// <summary>Checks the origin before the action runs.</summary>
    /// <param name="context">The action being invoked.</param>
    /// <param name="next">The rest of the pipeline.</param>
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        var request = context.HttpContext.Request;

        if (SafeMethods.Contains(request.Method, StringComparer.OrdinalIgnoreCase))
        {
            await next().ConfigureAwait(false);
            return;
        }

        var origin = request.Headers.Origin.ToString();

        if (string.IsNullOrEmpty(origin))
        {
            // Fall back to Referer's origin: some browsers omit Origin on same-origin requests.
            var referer = request.Headers.Referer.ToString();
            if (!string.IsNullOrEmpty(referer) && Uri.TryCreate(referer, UriKind.Absolute, out var uri))
            {
                origin = uri.GetLeftPart(UriPartial.Authority);
            }
        }

        if (!string.IsNullOrEmpty(origin) && !registry.IsAllowed(origin))
        {
            context.Result = new ObjectResult(new ProblemDetails
            {
                Status = StatusCodes.Status403Forbidden,
                Title = "Request origin is not allowed.",
            })
            {
                StatusCode = StatusCodes.Status403Forbidden,
            };

            return;
        }

        await next().ConfigureAwait(false);
    }
}
