using Crestacle.Sentinel.AspNetCore.Authorization;
using Crestacle.Sentinel.Core.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Crestacle.Sentinel.AspNetCore.Controllers;

[ApiController]
[Route("api/auth/profile")]
[Authorize]
public sealed class ProfileController(IUserRepository userRepository) : ControllerBase
{
    /// <summary>
    /// Returns the currently authenticated user's profile (email, name, roles) resolved
    /// from the database -- a non-JWT fallback for clients that don't carry profile claims in
    /// the access token (e.g. apps using <c>.WithPermissionClaims()</c> without
    /// <c>.WithProfileClaims()</c>, or neither).
    /// </summary>
    [HttpGet("me")]
    [ProducesResponseType<ProfileResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetMyProfile(CancellationToken cancellationToken)
    {
        var subject = User.GetSubject();

        if (string.IsNullOrWhiteSpace(subject))
            return Unauthorized();

        var user = await userRepository.GetByIdentityIdAsync(subject, cancellationToken);
        if (user is null)
            return NotFound();

        return Ok(new ProfileResponse(
            user.Email,
            user.FullName,
            user.Roles.Select(r => r.Name)));
    }
}

/// <remarks>
/// Deliberately omits Sentinel's internal <c>User.Id</c> -- it is a separate Guid from the
/// auth subject (<c>sub</c>/<c>user_id</c>) the caller already has on its own access token.
/// </remarks>
public sealed record ProfileResponse(
    string               Email,
    string?              FullName,
    IEnumerable<string>  Roles);
