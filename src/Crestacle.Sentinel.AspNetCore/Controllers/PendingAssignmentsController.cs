using System.ComponentModel.DataAnnotations;
using Crestacle.Sentinel.AspNetCore.Authorization;
using Crestacle.Sentinel.Core.Authorization;
using Crestacle.Sentinel.Core.DTOs;
using Crestacle.Sentinel.Core.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Crestacle.Sentinel.AspNetCore.Controllers;

/// <summary>
/// Manages role assignment requests that require dual-admin approval (4-Eyes principle).
/// Created automatically when a user is assigned to a role with RequiresDualApproval = true.
/// </summary>
[ApiController]
[Route("api/auth/pending-assignments")]
public sealed class PendingAssignmentsController(
    IPendingAssignmentRepository pendingAssignmentRepository) : ControllerBase
{
    [HttpGet]
    [MustHavePermission(SentinelFeature.User, AppAction.Read)]
    [ProducesResponseType<PagedResult<PendingAssignmentDto>>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> GetPending(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50,
        CancellationToken cancellationToken = default)
    {
        if (page < 1)        return BadRequest(new { error = "page must be >= 1." });
        if (pageSize is < 1 or > 200) return BadRequest(new { error = "pageSize must be between 1 and 200." });

        var pending = await pendingAssignmentRepository.GetPendingAsync(page, pageSize, cancellationToken);
        return Ok(pending);
    }

    /// <summary>
    /// Approves a pending role assignment.
    /// The approver must be a different user from the one who submitted the request.
    /// Returns 409 Conflict when the request cannot be approved (already reviewed, expired,
    /// or the approver is the same as the requestor).
    /// </summary>
    [HttpPost("{id:guid}/approve")]
    [MustHavePermission(SentinelFeature.User, AppAction.Update)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Approve(Guid id, CancellationToken cancellationToken)
    {
        var approved = await pendingAssignmentRepository.ApproveAsync(id, cancellationToken);
        return approved ? Ok() : Conflict();
    }

    /// <summary>
    /// Rejects a pending role assignment.
    /// The rejecter must be a different user from the one who submitted the request.
    /// Returns 409 Conflict when the request cannot be rejected (already reviewed, expired,
    /// or the rejecter is the same as the requestor).
    /// </summary>
    [HttpPost("{id:guid}/reject")]
    [MustHavePermission(SentinelFeature.User, AppAction.Update)]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Reject(
        Guid id,
        [FromBody] RejectAssignmentRequest request,
        CancellationToken cancellationToken)
    {
        var rejected = await pendingAssignmentRepository.RejectAsync(id, request.Reason, cancellationToken);
        return rejected ? Ok() : Conflict();
    }
}

// Matches PendingAssignment.RejectionReason's HasMaxLength(500) (PendingAssignmentConfiguration.cs).
public sealed record RejectAssignmentRequest(
    [StringLength(500)] string? Reason);
