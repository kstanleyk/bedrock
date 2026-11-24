namespace Crestacle.Bedrock.Core.Interfaces.Services;

/// <summary>Validates password complexity and enforces the reuse-prevention policy.</summary>
/// <remarks>
/// Both members are async so that an implementer backed by a remote call (e.g. a breach-database
/// lookup) can await it directly end-to-end, instead of bridging a synchronous API via
/// <c>Task.Run(...).GetAwaiter().GetResult()</c> -- a sync-over-async pattern that risks thread-pool
/// starvation under load. A purely synchronous implementer can still conform trivially by returning
/// <see cref="Task.FromResult{TResult}(TResult)"/>.
/// </remarks>
public interface IPasswordValidator
{
    /// <summary>
    /// Returns <c>true</c> when <paramref name="password"/> satisfies all configured complexity rules.
    /// The result's <c>Errors</c> list carries a human-readable description of each violation.
    /// </summary>
    /// <param name="password">The plaintext password to validate.</param>
    /// <param name="ct">Cancellation token for any remote call the validator makes.</param>
    /// <returns>
    /// A tuple whose <c>IsValid</c> is <c>true</c> when the password passes all rules, and whose
    /// <c>Errors</c> is empty in that case; when <c>IsValid</c> is <c>false</c>, <c>Errors</c> describes
    /// each violation.
    /// </returns>
    Task<(bool IsValid, IReadOnlyList<string> Errors)> IsValidAsync(string password, CancellationToken ct = default);

    /// <summary>
    /// Returns <c>true</c> when <paramref name="password"/> matches any of the previously stored hashes,
    /// indicating that reuse is not permitted. Uses constant-time comparison internally.
    /// </summary>
    /// <param name="password">The plaintext password to check for reuse.</param>
    /// <param name="hashes">The collection of previously stored password hashes to compare against.</param>
    /// <param name="ct">Cancellation token for any remote call the validator makes.</param>
    /// <returns><c>true</c> when the password has been used before; <c>false</c> when it is new.</returns>
    Task<bool> IsPreviouslyUsedAsync(string password, IEnumerable<string> hashes, CancellationToken ct = default);
}
