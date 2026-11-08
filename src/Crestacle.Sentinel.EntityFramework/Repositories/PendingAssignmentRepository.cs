using Crestacle.Sentinel.Core.DTOs;
using Crestacle.Sentinel.Core.Entities;
using Crestacle.Sentinel.Core.Enums;
using Crestacle.Sentinel.Core.Events;
using Crestacle.Sentinel.Core.Interfaces;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Crestacle.Sentinel.EntityFramework.Repositories;

internal sealed class PendingAssignmentRepository(
    IAuthDbContext                          context,
    ICurrentActor                           actor,
    IPermissionCache                        cache,
    ITenantContext                          tenantContext,
    ISentinelEventPublisher                 eventPublisher,
    ILogger<PendingAssignmentRepository>    logger)
    : IPendingAssignmentRepository
{
    public async Task<PagedResult<PendingAssignmentDto>> GetPendingAsync(
        int page = 1, int pageSize = 50, CancellationToken ct = default)
    {
        var tenantId = tenantContext.TenantId;
        var now      = DateTime.UtcNow;

        var query = context.PendingAssignments
            .AsNoTracking()
            .Where(pa => pa.Status    == AssignmentStatus.Pending
                      && pa.ExpiresOn > now
                      && (tenantId   == null || pa.TenantId == tenantId))
            .OrderBy(pa => pa.RequestedOn);

        var total = await query.CountAsync(ct);

        var items = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(pa => new PendingAssignmentDto(
                pa.Id, pa.UserId, pa.RoleId,
                pa.RequestedBy, pa.RequestedOn, pa.ExpiresOn,
                pa.Status.ToString(), pa.ReviewedBy, pa.ReviewedOn, pa.RejectionReason,
                pa.RoleExpiresOn))
            .ToListAsync(ct);

        return new PagedResult<PendingAssignmentDto>(items, page, pageSize, total);
    }

    public async Task<PendingAssignment?> GetByIdAsync(Guid id, CancellationToken ct = default)
        => await context.PendingAssignments.FindAsync([id], ct);

    public async Task<PendingAssignment> CreateAsync(Guid userId, Guid roleId, DateTime? roleExpiresOn = null, CancellationToken ct = default)
    {
        var pending = PendingAssignment.Create(
            userId,
            roleId,
            actor.IdentityId ?? "system",
            tenantContext.TenantId,
            roleExpiresOn);

        context.PendingAssignments.Add(pending);
        await context.SaveChangesAsync(ct);
        return pending;
    }

    public async Task<bool> ApproveAsync(Guid id, CancellationToken ct = default)
    {
        var pending = await context.PendingAssignments.FindAsync([id], ct);
        if (pending is null)
            return false;

        var reviewer = actor.IdentityId ?? "system";

        // Enforce 4-Eyes: the approver must be different from the requestor.
        if (pending.RequestedBy == reviewer)
            return false;

        if (!pending.Approve(reviewer))
            return false;

        var tenantId   = pending.TenantId;
        var identityId = await context.Users
            .Where(u => u.Id == pending.UserId)
            .Select(u => u.IdentityId)
            .FirstOrDefaultAsync(ct);

        // Create the actual role assignment atomically with the approval.
        // RoleExpiresOn carries the time-bound constraint submitted by the original requestor.
        context.UserRoles.Add(new UserRole
        {
            Id        = Guid.NewGuid(),
            UserId    = pending.UserId,
            RoleId    = pending.RoleId,
            CreatedOn = DateTime.UtcNow,
            ExpiresOn = pending.RoleExpiresOn,
            TenantId  = tenantId,
        });

        context.AuditLog.Add(AuditEntry.Create(
            AuditAction.RoleAssigned,
            $"{pending.UserId}/{pending.RoleId}",
            reviewer,
            actor.IpAddress,
            actor.UserAgent));

        // Explicit transaction boundary: the PendingAssignment status change and the
        // new UserRole are two separate aggregates and must commit or roll back together.
        // The in-memory provider (used in unit tests) doesn't support real transactions,
        // so skip wrapping there — a single SaveChangesAsync is already atomic on it.
        var useTransaction = context.Database.IsRelational();
        var transaction = useTransaction ? await context.Database.BeginTransactionAsync(ct) : null;
        try
        {
            await context.SaveChangesAsync(ct);
            if (transaction is not null)
                await transaction.CommitAsync(ct);
        }
        catch (DbUpdateConcurrencyException)
        {
            // Another approver saved first — our RowVersion is stale.
            if (transaction is not null)
                await transaction.RollbackAsync(ct);
            logger.LogWarning("Concurrency conflict approving pending assignment {Id} — another approver saved first.", id);
            return false;
        }
        finally
        {
            if (transaction is not null)
                await transaction.DisposeAsync();
        }

        logger.LogInformation("Pending assignment {Id} approved by {Reviewer}.", id, reviewer);

        if (identityId is not null)
            await cache.InvalidateUserAsync(identityId, ct);

        await eventPublisher.PublishAsync(
            new AssignmentApprovedEvent(id, pending.UserId, identityId, pending.RoleId, pending.TenantId, reviewer, DateTime.UtcNow, pending.RoleExpiresOn), ct);

        return true;
    }

    public async Task<bool> RejectAsync(Guid id, string? reason, CancellationToken ct = default)
    {
        var pending = await context.PendingAssignments.FindAsync([id], ct);
        if (pending is null)
            return false;

        var reviewer = actor.IdentityId ?? "system";

        // Enforce 4-Eyes: the rejecter must be different from the requestor.
        if (pending.RequestedBy == reviewer)
            return false;

        if (!pending.Reject(reviewer, reason))
            return false;

        try
        {
            await context.SaveChangesAsync(ct);
        }
        catch (DbUpdateConcurrencyException)
        {
            logger.LogWarning("Concurrency conflict rejecting pending assignment {Id}.", id);
            return false;
        }

        logger.LogInformation("Pending assignment {Id} rejected by {Reviewer}.", id, reviewer);
        return true;
    }

    public async Task MarkExpiredBatchAsync(CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;

        var count = await context.PendingAssignments
            .Where(pa => pa.Status == AssignmentStatus.Pending && pa.ExpiresOn <= now)
            .ExecuteUpdateAsync(
                s => s.SetProperty(pa => pa.Status, AssignmentStatus.Expired), ct);

        if (count == 0)
            logger.LogDebug("Expiry sweep: no pending assignments to expire.");
        else
            logger.LogInformation("Expiry sweep: marked {Count} pending assignment(s) as expired.", count);
    }
}
