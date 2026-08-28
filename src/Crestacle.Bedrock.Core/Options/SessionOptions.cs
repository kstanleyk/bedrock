namespace Crestacle.Bedrock.Core.Options;

/// <summary>
/// Mirrors <c>Microsoft.AspNetCore.Http.SameSiteMode</c> without pulling an ASP.NET Core
/// dependency into this project — the AspNetCore layer maps this onto the real enum when it
/// builds the refresh cookie's <c>CookieOptions</c>.
/// </summary>
public enum RefreshCookieSameSitePolicy
{
    Strict,
    Lax,
    None,
}

/// <summary>Per-user session management settings.</summary>
public sealed class SessionOptions
{
    /// <summary>
    /// Maximum number of concurrent active sessions per user.
    /// When the limit is reached the oldest session is evicted on new login. Default: 5.
    /// </summary>
    public int MaxConcurrentSessions { get; set; } = 5;

    /// <summary>
    /// Hard cap on how long any single session may remain active, regardless of how often
    /// it is refreshed. Once <c>Session.CreatedAt + AbsoluteRefreshExpiry</c> is in the past
    /// the next refresh attempt is rejected with <c>session_expired</c> and the user must
    /// re-authenticate. <c>null</c> (default) disables the absolute cap.
    /// </summary>
    public TimeSpan? AbsoluteRefreshExpiry { get; set; }

    /// <summary>
    /// <c>SameSite</c> policy for the refresh-token cookie. Default: <c>None</c> (with the
    /// cookie always <c>Secure</c> and <c>HttpOnly</c>) — the common case is a frontend and API
    /// on different origins (e.g. a Vite dev server on http://localhost:3000 talking to an API
    /// on https://localhost:7104), which browsers treat as cross-site under schemeful-same-site
    /// rules even when the hostname is identical; <c>Strict</c>/<c>Lax</c> silently drop the
    /// cookie on every cross-site refresh request in that setup. Set to <c>Strict</c> or
    /// <c>Lax</c> only when the consuming app's frontend and API genuinely share a site.
    /// </summary>
    public RefreshCookieSameSitePolicy RefreshCookieSameSite { get; set; } = RefreshCookieSameSitePolicy.None;
}
