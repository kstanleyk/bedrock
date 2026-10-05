using Crestacle.Bedrock.Core.DTOs;
using Crestacle.Bedrock.Core.Exceptions;

namespace Crestacle.Bedrock.Core.Interfaces.Services;

/// <summary>
/// Creates and accepts admin-issued invitations. An invitation grants a specific email
/// address the ability to register without going through open registration.
/// </summary>
public interface IInvitationService
{
    /// <summary>
    /// Creates a time-limited invitation for <paramref name="targetEmail"/> and sends an
    /// invitation email containing the acceptance link. Writes an <c>InvitationCreated</c>
    /// audit entry.
    /// </summary>
    /// <param name="invitedByUserId">The admin issuing the invitation, or <c>null</c> for system-generated invitations.</param>
    /// <param name="targetEmail">The email address being invited.</param>
    /// <param name="roleHint">Optional role to assign on acceptance.</param>
    /// <param name="ipAddress">The requesting IP address, recorded in the audit log.</param>
    /// <param name="ct">Cancellation token.</param>
    Task CreateInvitationAsync(
        Guid? invitedByUserId,
        string targetEmail,
        string? roleHint,
        string ipAddress,
        CancellationToken ct = default);

    /// <summary>
    /// Accepts a pending invitation: registers the user, auto-confirms their email,
    /// marks the invitation as accepted, writes an <c>InvitationAccepted</c> audit entry,
    /// and issues login tokens.
    /// </summary>
    /// <param name="rawToken">The raw invitation token from the acceptance link (not pre-hashed).</param>
    /// <param name="password">The plaintext password chosen by the new user.</param>
    /// <param name="ipAddress">The requesting IP address, recorded in the audit log.</param>
    /// <param name="userAgent">The User-Agent header of the request.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>A <see cref="TokenPair"/> the client can use immediately.</returns>
    /// <exception cref="BedrockValidationException">
    /// Thrown when the token is unknown, already accepted, or expired; or when the
    /// password fails complexity validation.
    /// </exception>
    Task<TokenPair> AcceptInvitationAsync(
        string rawToken,
        string password,
        string ipAddress,
        string userAgent,
        CancellationToken ct = default);
}
