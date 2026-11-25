using Crestacle.Sentinel.AspNetCore.Authorization;
using Crestacle.Sentinel.Core.Authorization;
using Crestacle.Sentinel.Core.DTOs;
using Crestacle.Sentinel.Core.Exceptions;
using Crestacle.Sentinel.Core.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Crestacle.Sentinel.AspNetCore.Controllers;

[ApiController]
[Route("api/auth/users")]
public sealed class UsersController(
    IUserRepository              userRepository,
    IRoleRepository              roleRepository,
    IPendingAssignmentRepository pendingAssignmentRepository,
    IUserPermissionRepository    userPermissionRepository) : ControllerBase
{
    [HttpGet]
    [MustHavePermission(SentinelFeature.User, AppAction.Read)]
    [ProducesResponseType<PagedResult<UserDto>>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> GetUsers(
        [FromQuery] int     page     = 1,
        [FromQuery] int     pageSize = 50,
        [FromQuery] string? search   = null,
        CancellationToken cancellationToken = default)
    {
        if (page < 1)        return BadRequest(new { error = "page must be >= 1." });
        if (pageSize is < 1 or > 200) return BadRequest(new { error = "pageSize must be between 1 and 200." });

        var users = await userRepository.GetAllWithRolesAsync(page, pageSize, search, cancellationToken);
        return Ok(users);
    }

    [HttpGet("{id:guid}")]
    [MustHavePermission(SentinelFeature.User, AppAction.Read)]
    [ProducesResponseType<UserDto>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetUser(Guid id, CancellationToken cancellationToken = default)
    {
        var user = await userRepository.GetByIdAsync(id, cancellationToken);
        return user is null ? NotFound() : Ok(user);
    }

    /// <summary>
    /// Assigns a role to a user.
    /// When the role has RequiresDualApproval = true the assignment is held as a
    /// PendingAssignment and 202 Accepted is returned with the pending request ID.
    /// A second admin must then approve via POST /api/auth/pending-assignments/{id}/approve.
    /// An optional ExpiresOn can be provided for time-bound access.
    /// </summary>
    [HttpPost("{id:guid}/roles")]
    [MustHavePermission(SentinelFeature.User, AppAction.Update)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status202Accepted)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> AssignRole(
        Guid id,
        [FromBody] AssignRoleRequest request,
        CancellationToken cancellationToken)
    {
        if (request.RoleId == Guid.Empty)
            return BadRequest(new { error = "roleId is required." });

        if (request.ExpiresOn.HasValue && request.ExpiresOn.Value <= DateTime.UtcNow)
            return BadRequest(new { error = "expiresOn must be a future date." });

        // Guard: an actor cannot modify their own role assignments.
        if (await IsSelfAsync(id, cancellationToken))
            return Forbid();

        // Guard: an actor may only assign a role whose permissions they themselves hold --
        // mirrors RolesController.AssignPermission's symmetric guard. Without this, a user
        // who only has User.Update (but none of the role's own permissions) could launder a
        // privilege escalation by assigning a highly-privileged role to a colluding account.
        if (!await ActorHoldsAllRolePermissionsAsync(request.RoleId, cancellationToken))
            return Forbid();

        // 4-Eyes: if the target role requires dual approval, create a pending request instead.
        // ExpiresOn is preserved so the approver creates a time-bound assignment.
        if (await roleRepository.RequiresDualApprovalAsync(request.RoleId, cancellationToken))
        {
            var pending = await pendingAssignmentRepository.CreateAsync(id, request.RoleId, request.ExpiresOn, cancellationToken);
            return Accepted(new { pendingAssignmentId = pending.Id });
        }

        try
        {
            await userRepository.AddRoleAsync(id, request.RoleId, request.ExpiresOn, cancellationToken);
        }
        catch (SentinelNotFoundException ex)
        {
            return NotFound(new { error = ex.Message });
        }

        return Ok();
    }

    [HttpDelete("{id:guid}/roles/{roleId:guid}")]
    [MustHavePermission(SentinelFeature.User, AppAction.Update)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> RemoveRole(
        Guid id,
        Guid roleId,
        CancellationToken cancellationToken)
    {
        // Guard: an actor cannot modify their own role assignments.
        if (await IsSelfAsync(id, cancellationToken))
            return Forbid();

        await userRepository.RemoveRoleAsync(id, roleId, cancellationToken);
        return Ok();
    }

    private async Task<bool> IsSelfAsync(Guid targetUserId, CancellationToken ct)
    {
        var callerSubject = User.GetSubject();
        if (string.IsNullOrEmpty(callerSubject))
            return false;

        var targetIdentityId = await userRepository.GetIdentityIdAsync(targetUserId, ct);
        return targetIdentityId == callerSubject;
    }

    private async Task<bool> ActorHoldsAllRolePermissionsAsync(Guid roleId, CancellationToken ct)
    {
        var subject = User.GetSubject();
        if (string.IsNullOrEmpty(subject))
            return false;

        var role = await roleRepository.GetByIdAsync(roleId, ct);
        if (role is null)
            return true; // let AddRoleAsync's own not-found handling produce the 404

        var actorPermissions = await userPermissionRepository.GetPermissionsForUserAsync(subject, ct);
        return role.Permissions.All(p => actorPermissions.Contains(p.Id));
    }
}

// RoleId (bare Guid) and ExpiresOn (nullable DateTime) have no meaningful DataAnnotations
// constraint to add -- same bare-Guid convention as VerifyStepUpRequest.ChallengeId elsewhere in
// this change-set. RoleId == Guid.Empty is already explicitly guarded in AssignRoleAsync above.
public sealed record AssignRoleRequest(Guid RoleId, DateTime? ExpiresOn = null);
