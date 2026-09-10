namespace Pluperfect.Jwt;

/// <summary>
/// The browser origins permitted to make state-changing requests.
/// </summary>
/// <remarks>
/// ⚠ Never a wildcard. The CORS policy that accompanies a cookie transport sends credentials, and
/// <c>Access-Control-Allow-Origin: *</c> with credentials is rejected by every browser — so an
/// allow-list is not merely the safer choice, it is the only one that works.
/// </remarks>
public sealed class AllowedOriginRegistry
{
    private readonly HashSet<string> _origins;

    /// <summary>Builds a registry from configured origins.</summary>
    /// <param name="origins">
    /// Absolute origins, scheme and authority only — <c>https://example.com</c>, never a path.
    /// Compared case-insensitively and without a trailing slash.
    /// </param>
    /// <exception cref="ArgumentException">The list is empty.</exception>
    public AllowedOriginRegistry(IEnumerable<string> origins)
    {
        ArgumentNullException.ThrowIfNull(origins);

        _origins = origins
            .Where(o => !string.IsNullOrWhiteSpace(o))
            .Select(o => o.TrimEnd('/'))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        // An empty allow-list permits nothing, which from the browser is indistinguishable from a
        // CORS bug. Failing here means it is reported as configuration instead.
        if (_origins.Count == 0)
        {
            throw new ArgumentException(
                "No allowed origins were configured. An empty list rejects every browser request "
                + "and surfaces as an unexplained CORS failure rather than as a startup error.",
                nameof(origins));
        }
    }

    /// <summary>Whether an origin may make state-changing requests.</summary>
    /// <param name="origin">The value of the <c>Origin</c> header, or an authority derived from <c>Referer</c>.</param>
    /// <returns><c>true</c> when it is on the list.</returns>
    public bool IsAllowed(string? origin) =>
        !string.IsNullOrEmpty(origin) && _origins.Contains(origin.TrimEnd('/'));

    /// <summary>The configured origins, for handing to a CORS policy.</summary>
    /// <returns>A copy; the registry is not mutable through it.</returns>
    public string[] ToArray() => [.. _origins];
}
