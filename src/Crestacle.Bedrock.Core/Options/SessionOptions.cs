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

    /// <summary>
    /// Cookie <c>Path</c> for the refresh-token cookie (<c>omni_refresh</c>). Default:
    /// <c>"/api/v1/auth"</c> — matches this library's own default consumer wiring
    /// (<c>AddBedrockControllers("api/v1")</c>, whose <c>BedrockAuthController</c> mounts at
    /// <c>auth</c>), preserved as the default so existing consumers see no behavior change.
    /// <para>
    /// Every action that sets or deletes this cookie (<c>BedrockAuthController</c>'s
    /// Login/Refresh/Revoke/Verify2FA/etc., <c>BedrockPasskeyController</c>'s own passkey
    /// login) uses this SAME value — the cookie has exactly one <c>Path</c> across the whole
    /// library, never a different one per action. This matters when narrowing it: the value
    /// must cover every route that READS the cookie back, not just the route it is
    /// conceptually "for" — today that is <c>Refresh</c> and <c>Revoke</c> (both do
    /// <c>Request.Cookies["omni_refresh"]</c>); a value that excludes either one breaks that
    /// flow. Narrowing to a value that excludes a route the cookie is only ever WRITTEN from
    /// (Login, Verify2FA, passkey login, ...) is safe — those never read it back.
    /// </para>
    /// <para>
    /// Consumers whose <c>AddBedrockControllers</c> basePath differs from this library's own
    /// default MUST set this explicitly to their real computed route prefix — the previous
    /// hardcoded literal silently assumed the default basePath and produced a cookie pointing
    /// at a URL that didn't match a consumer's actual routes if they chose differently, with
    /// no way to correct it short of forking this controller.
    /// </para>
    /// </summary>
    public string RefreshCookiePath { get; set; } = "/api/v1/auth";

    /// <summary>
    /// Cookie name for the refresh token. Default: <c>"omni_refresh"</c> (this library's own
    /// original hardcoded literal, preserved as the default so existing consumers see no
    /// behavior change). Consumers with their own naming convention (e.g. an
    /// <c>__Secure-</c>-prefixed name distinguishing realms) should set this explicitly;
    /// every action that sets, reads, or deletes the cookie (<c>BedrockAuthController</c>'s
    /// Login/Refresh/Revoke/Verify2FA/etc., <c>BedrockPasskeyController</c>'s own passkey
    /// login) uses this SAME configured name consistently.
    /// </summary>
    public string RefreshCookieName { get; set; } = "omni_refresh";
}
