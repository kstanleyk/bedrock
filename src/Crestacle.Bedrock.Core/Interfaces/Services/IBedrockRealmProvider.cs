using Crestacle.Bedrock.Core.Realm;

namespace Crestacle.Bedrock.Core.Interfaces.Services;

/// <summary>
/// Resolves the current request's <see cref="BedrockRealm"/> from the incoming <c>Host</c>
/// header, for a single Bedrock deployment serving more than one distinct user population.
/// The default registration (<c>SingleRealmProvider</c>) always resolves the same
/// no-realm-concept <see cref="BedrockRealm"/> regardless of host — every existing
/// single-realm consumer sees zero behavior change unless it registers its own
/// implementation via <c>WithRealmProvider&lt;T&gt;</c>.
/// </summary>
public interface IBedrockRealmProvider
{
    /// <summary>
    /// Resolves the realm for the given <c>Host</c> header value (host only, no port —
    /// <c>HttpRequest.Host.Host</c>, not <c>HttpRequest.Host.Value</c>).
    /// </summary>
    /// <param name="host">The incoming request's <c>Host</c> header value, or <see langword="null"/> if absent.</param>
    /// <returns>
    /// The resolved <see cref="BedrockRealm"/>, or <see langword="null"/> if <paramref name="host"/>
    /// does not map to any configured realm — callers that must fail closed on an unrecognized
    /// host (rather than silently falling back to base <c>BedrockOptions</c> values) should treat
    /// a <see langword="null"/> result as a hard rejection, not a default.
    /// </returns>
    BedrockRealm? Resolve(string? host);
}
