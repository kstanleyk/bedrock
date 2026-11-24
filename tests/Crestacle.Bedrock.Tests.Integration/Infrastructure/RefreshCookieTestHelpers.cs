namespace Crestacle.Bedrock.Tests.Integration.Infrastructure;

/// <summary>
/// The refresh token is HttpOnly-cookie-only (never present in a JSON response body) since the
/// June 2026 cookie hardening. <see cref="BedrockTestServer"/>'s <see cref="HttpClient"/> has no
/// cookie jar, so a test driving a multi-request flow (login -&gt; refresh -&gt; revoke, etc.) must
/// read the real <c>Set-Cookie</c> header and manually carry the value forward itself, the same
/// way a real browser's cookie jar would -- these helpers do exactly that, nothing more.
/// </summary>
internal static class RefreshCookieTestHelpers
{
    /// <summary>Matches <c>SessionOptions.RefreshCookieName</c>'s compiled default.</summary>
    public const string CookieName = "omni_refresh";

    /// <summary>Extracts the raw refresh-token value from a response's <c>Set-Cookie</c> header, or null if absent.</summary>
    public static string? GetRefreshCookieValue(this HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var setCookieHeaders))
            return null;

        foreach (var header in setCookieHeaders)
        {
            var firstSegment = header.Split(';', 2)[0];
            var separator = firstSegment.IndexOf('=');
            if (separator <= 0) continue;

            var name = firstSegment[..separator];
            if (name == CookieName)
                return firstSegment[(separator + 1)..];
        }

        return null;
    }

    /// <summary>True when the response's <c>Set-Cookie</c> header deletes the refresh cookie (empty value / past expiry).</summary>
    public static bool DeletesRefreshCookie(this HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var setCookieHeaders))
            return false;

        return setCookieHeaders.Any(h =>
            h.StartsWith($"{CookieName}=", StringComparison.Ordinal) &&
            (h.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase) ||
             h.Split(';', 2)[0] == $"{CookieName}="));
    }

    /// <summary>
    /// Sets (or clears, passing null) the client's outgoing refresh cookie for every subsequent
    /// request, mirroring the <c>SetBearer</c> pattern already used elsewhere in this test suite
    /// for the Authorization header.
    /// </summary>
    public static void SetRefreshCookie(this HttpClient client, string? value)
    {
        client.DefaultRequestHeaders.Remove("Cookie");
        if (value is not null)
            client.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", $"{CookieName}={value}");
    }
}
