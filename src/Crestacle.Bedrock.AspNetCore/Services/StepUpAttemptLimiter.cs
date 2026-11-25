using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.Core.Options;
using Microsoft.Extensions.Options;

namespace Crestacle.Bedrock.AspNetCore.Services;

/// <summary>
/// Throttles OTP/TOTP verification attempts against a single step-up challenge using the
/// Bedrock cache. Cache key: <c>Bedrock:stepup-attempt-count:{challengeId}</c>.
/// Unlike <see cref="OtpSendLimiter"/> (which guards how many codes get SENT), this guards how
/// many times a single already-issued challenge may be guessed against before it is invalidated.
/// </summary>
public sealed class StepUpAttemptLimiter
{
    private const string KeyPrefix = "Bedrock:stepup-attempt-count:";

    private readonly IBedrockCache _cache;
    private readonly BedrockOptions _options;

    public StepUpAttemptLimiter(IBedrockCache cache, IOptions<BedrockOptions> options)
    {
        _cache = cache;
        _options = options.Value;
    }

    /// <summary>
    /// Records one failed verification attempt against <paramref name="challengeId"/> and
    /// returns <see langword="true"/> once the configured maximum (<see cref="LockoutOptions.MaxStepUpVerifyAttempts"/>)
    /// has been exceeded. The counter's TTL matches the step-up token's own expiry
    /// (<see cref="TokenExpiryOptions.StepUpToken"/>), so it never outlives the challenge it guards.
    /// </summary>
    public async Task<bool> RecordFailureAndCheckAsync(Guid challengeId, CancellationToken ct = default)
    {
        var key = $"{KeyPrefix}{challengeId}";
        var raw = await _cache.GetAsync(key, ct);
        var count = (raw is null ? 0 : int.Parse(raw)) + 1;

        await _cache.SetAsync(key, count.ToString(), _options.TokenExpiry.StepUpToken, ct);

        return count > _options.Lockout.MaxStepUpVerifyAttempts;
    }
}
