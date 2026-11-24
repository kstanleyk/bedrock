using Crestacle.Bedrock.Core;

namespace Crestacle.Bedrock.Core.Exceptions;

/// <summary>
/// Thrown when authentication is attempted against a locked account.
/// Maps to HTTP 423 Locked. The <see cref="LockoutEnd"/> value is used to
/// populate the <c>Retry-After</c> response header.
/// </summary>
public sealed class BedrockAccountLockedException : BedrockException
{
    /// <summary>UTC timestamp when the lockout expires.</summary>
    public DateTime LockoutEnd { get; }

    /// <summary>
    /// True when the lockout was set by an administrator (<see cref="Entities.UserCredential.AdminLock"/>)
    /// rather than the automatic timed lockout. The message is generic in that case — admin locks use a
    /// 100-year-out <see cref="LockoutEnd"/> sentinel purely to keep <c>IsLockedOut()</c> true
    /// indefinitely, and that raw far-future date must never be interpolated into a user-facing message.
    /// </summary>
    public bool IsAdminLocked { get; }

    public BedrockAccountLockedException(DateTime lockoutEnd, bool isAdminLocked = false)
        : base(
            isAdminLocked
                ? "Your account has been locked by an administrator. Contact support."
                : $"Account is locked until {lockoutEnd:O}.",
            BedrockErrorCodes.AccountLocked)
    {
        LockoutEnd = lockoutEnd;
        IsAdminLocked = isAdminLocked;
    }
}
