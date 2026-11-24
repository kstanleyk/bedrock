using Crestacle.Bedrock.Core.Entities;

namespace Crestacle.Bedrock.Core.Interfaces.Services;

/// <summary>Evaluates the mandatory MFA policy for a given credential.</summary>
public interface IMfaPolicyService
{
    /// <summary>
    /// Returns true when mandatory MFA is configured. This is currently a global gate, NOT
    /// per-role scoped: a non-empty <c>MandatoryRoles</c> makes MFA mandatory for every
    /// credential, regardless of which role (if any) it actually holds. <c>Crestacle.Bedrock.Core</c>
    /// has no concept of roles (that's a Sentinel/RBAC concern in a separate package it does not
    /// depend on), so <paramref name="credential"/> cannot be checked against
    /// <c>MandatoryRoles</c> membership here. The parameter exists for realm-aware resolution
    /// (see the default implementation's remarks) and for forward-compatibility, not because it
    /// is evaluated today.
    /// </summary>
    /// <param name="credential">The credential to evaluate.</param>
    /// <returns><see langword="true"/> when at least one mandatory role is configured, for ANY credential.</returns>
    bool IsMfaRequired(UserCredential credential);

    /// <summary>Returns true when the grace period has been set and has not yet expired.</summary>
    /// <param name="credential">The credential to check.</param>
    /// <returns><see langword="true"/> when <c>MfaGracePeriodEnd</c> is set and in the future.</returns>
    bool IsInGracePeriod(UserCredential credential);

    /// <summary>Returns true when the grace period was set and has since expired.</summary>
    /// <param name="credential">The credential to check.</param>
    /// <returns><see langword="true"/> when <c>MfaGracePeriodEnd</c> is set and in the past.</returns>
    bool GracePeriodExpired(UserCredential credential);

    /// <summary>Computes the grace period end date as UtcNow + GracePeriodDays.</summary>
    /// <returns>The UTC timestamp at which the grace period ends for a user enrolled today.</returns>
    DateTime ComputeGracePeriodEnd();

    /// <summary>
    /// Sets the MFA grace period on <paramref name="credential"/> using the configured
    /// <c>GracePeriodDays</c> and returns the computed end timestamp.
    /// </summary>
    /// <param name="credential">The credential whose grace period to initialise.</param>
    /// <returns>The UTC timestamp at which the grace period ends.</returns>
    DateTime SetGracePeriod(UserCredential credential);
}
