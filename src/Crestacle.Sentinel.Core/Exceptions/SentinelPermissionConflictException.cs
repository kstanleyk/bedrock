namespace Crestacle.Sentinel.Core.Exceptions;

/// <summary>
/// Thrown when adding a permission to a role would violate a registered Separation-of-Duties
/// conflict. Surface this as HTTP 409 Conflict in your exception-handling middleware.
/// </summary>
public sealed class SentinelPermissionConflictException : Exception
{
    public SentinelPermissionConflictException(string message) : base(message) { }
}
