using System.ComponentModel.DataAnnotations;
using Crestacle.Sentinel.AspNetCore.Authorization;
using Crestacle.Sentinel.Core.Authorization;
using Crestacle.Sentinel.Core.DTOs;
using Crestacle.Sentinel.Core.Enums;
using Crestacle.Sentinel.Core.Exceptions;
using Crestacle.Sentinel.Core.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Crestacle.Sentinel.AspNetCore.Controllers;

[ApiController]
[Route("api/auth/roles")]
public sealed class RolesController(
    IRoleRepository              roleRepository,
    IUserPermissionRepository    userPermissionRepository,
    IPermissionConflictRepository conflictRepository) : ControllerBase
{
    [HttpGet]
    [MustHavePermission(SentinelFeature.Role, AppAction.Read)]
    [ProducesResponseType<PagedResult<RoleDto>>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> GetRoles(
        [FromQuery] int     page     = 1,
        [FromQuery] int     pageSize = 50,
        [FromQuery] string? search   = null,
        CancellationToken cancellationToken = default)
    {
        if (page < 1)        return BadRequest(new { error = "page must be >= 1." });
        if (pageSize is < 1 or > 200) return BadRequest(new { error = "pageSize must be between 1 and 200." });

        var roles = await roleRepository.GetAllWithPermissionsAsync(page, pageSize, search, cancellationToken);
        return Ok(roles);
    }

    [HttpGet("{id:guid}")]
    [MustHavePermission(SentinelFeature.Role, AppAction.Read)]
    [ProducesResponseType<RoleDto>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetRole(Guid id, CancellationToken cancellationToken = default)
    {
        var role = await roleRepository.GetByIdAsync(id, cancellationToken);
        return role is null ? NotFound() : Ok(role);
    }

    [HttpPost("{id:guid}/permissions")]
    [MustHavePermission(SentinelFeature.Role, AppAction.Update)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> AssignPermission(
        Guid id,
        [FromBody] AssignPermissionRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.PermissionId))
            return BadRequest(new { error = "permissionId is required." });

        // Guard: Internal roles are immutable via the API.
        if (await IsProtectedRoleAsync(id, cancellationToken))
            return Forbid();

        // Guard: An actor may only grant permissions they themselves hold.
        if (!await ActorHoldsPermissionAsync(request.PermissionId, cancellationToken))
            return Forbid();

        // Guard: Separation of Duties — reject if this permission conflicts with an existing one on the role.
        if (await conflictRepository.HasConflictAsync(id, request.PermissionId, cancellationToken))
            return Conflict(new { error = "This permission conflicts with an existing permission on the role (Separation of Duties)." });

        try
        {
            await roleRepository.AddPermissionAsync(id, request.PermissionId, cancellationToken);
        }
        catch (SentinelNotFoundException ex)
        {
            return NotFound(new { error = ex.Message });
        }
        catch (SentinelPermissionConflictException ex)
        {
            // Backstop for the pre-check above: under true concurrency, two requests can both
            // pass the pre-check before either commits. AddPermissionAsync re-checks for SoD
            // conflicts inside its own transaction, so this is reachable even though the
            // pre-check already returned Conflict for the common (non-racing) case.
            return Conflict(new { error = ex.Message });
        }
        catch (SentinelConcurrencyException)
        {
            return Conflict(new { error = "The role was modified by another request. Please retry." });
        }

        return Ok();
    }

    [HttpDelete("{id:guid}/permissions/{permissionId}")]
    [MustHavePermission(SentinelFeature.Role, AppAction.Update)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> RemovePermission(
        Guid id,
        string permissionId,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(permissionId))
            return BadRequest(new { error = "permissionId is required." });

        // Guard: Internal roles are immutable via the API.
        if (await IsProtectedRoleAsync(id, cancellationToken))
            return Forbid();

        try
        {
            await roleRepository.RemovePermissionAsync(id, permissionId, cancellationToken);
        }
        catch (SentinelConcurrencyException)
        {
            return Conflict(new { error = "The role was modified by another request. Please retry." });
        }

        return Ok();
    }

    private async Task<bool> IsProtectedRoleAsync(Guid roleId, CancellationToken ct)
    {
        var type = await roleRepository.GetRoleTypeAsync(roleId, ct);
        return type == RoleType.Internal;
    }

    private async Task<bool> ActorHoldsPermissionAsync(string permissionId, CancellationToken ct)
    {
        var subject = User.GetSubject();
        if (string.IsNullOrEmpty(subject))
            return false;

        var actorPermissions = await userPermissionRepository.GetPermissionsForUserAsync(subject, ct);
        return actorPermissions.Contains(permissionId);
    }
}

// Permission.Id is a composite "feature.action"-style key stored with HasMaxLength(150)
// (PermissionConfiguration.cs) — mirrored here.
public sealed record AssignPermissionRequest(
    [Required, StringLength(150)] string PermissionId);
