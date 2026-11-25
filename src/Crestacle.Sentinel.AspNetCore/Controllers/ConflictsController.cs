using System.ComponentModel.DataAnnotations;
using Crestacle.Sentinel.AspNetCore.Authorization;
using Crestacle.Sentinel.Core.Authorization;
using Crestacle.Sentinel.Core.DTOs;
using Crestacle.Sentinel.Core.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Crestacle.Sentinel.AspNetCore.Controllers;

/// <summary>
/// Manages Separation of Duties conflict pairs.
/// A conflict pair prevents both permissions from being assigned to the same role simultaneously.
/// </summary>
[ApiController]
[Route("api/auth/conflicts")]
public sealed class ConflictsController(IPermissionConflictRepository conflictRepository) : ControllerBase
{
    [HttpGet]
    [MustHavePermission(SentinelFeature.Role, AppAction.Read)]
    [ProducesResponseType<IEnumerable<PermissionConflictDto>>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> GetConflicts(CancellationToken cancellationToken)
    {
        var conflicts = await conflictRepository.GetAllAsync(cancellationToken);
        return Ok(conflicts);
    }

    [HttpPost]
    [MustHavePermission(SentinelFeature.Role, AppAction.Update)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> AddConflict(
        [FromBody] AddConflictRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.PermissionIdA) || string.IsNullOrWhiteSpace(request.PermissionIdB))
            return BadRequest(new { error = "Both permissionIdA and permissionIdB are required." });

        if (string.Equals(request.PermissionIdA, request.PermissionIdB, StringComparison.OrdinalIgnoreCase))
            return BadRequest(new { error = "A permission cannot conflict with itself." });

        await conflictRepository.AddConflictAsync(request.PermissionIdA, request.PermissionIdB, cancellationToken);
        return Ok();
    }

    [HttpDelete("{id:guid}")]
    [MustHavePermission(SentinelFeature.Role, AppAction.Update)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> RemoveConflict(Guid id, CancellationToken cancellationToken)
    {
        await conflictRepository.RemoveConflictAsync(id, cancellationToken);
        return Ok();
    }
}

// Matches Permission.Id's HasMaxLength(150) (PermissionConfiguration.cs).
public sealed record AddConflictRequest(
    [Required, StringLength(150)] string PermissionIdA,
    [Required, StringLength(150)] string PermissionIdB);
