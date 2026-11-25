namespace Crestacle.Bedrock.Core.Options;

/// <summary>Account lockout policy settings.</summary>
public sealed class LockoutOptions
{
    /// <summary>
    /// Number of consecutive failed login attempts that triggers a lockout. Default: 5.
    /// </summary>
    public int MaxFailedAttempts { get; set; } = 5;

    /// <summary>Duration of the lockout window. Default: 15 minutes.</summary>
    public TimeSpan Duration { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Maximum wrong-code attempts allowed against a single step-up challenge before it is
    /// invalidated outright (see <c>StepUpAttemptLimiter</c>/<c>StepUpService.VerifyAsync</c>).
    /// Default: 5.
    /// </summary>
    public int MaxStepUpVerifyAttempts { get; set; } = 5;
}
