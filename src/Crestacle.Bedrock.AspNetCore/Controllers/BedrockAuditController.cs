using Crestacle.Bedrock.AspNetCore.Authorization;
using Crestacle.Bedrock.AspNetCore.Models;
using Crestacle.Bedrock.Core.DTOs;
using Crestacle.Bedrock.Core.Enumerations;
using Crestacle.Bedrock.Core.Interfaces.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Crestacle.Bedrock.AspNetCore.Controllers;

[ApiController]
[Route("audit")]
[Authorize(Policy = BedrockPolicyNames.Admin)]
public sealed class BedrockAuditController : ControllerBase
{
    private readonly IAuditRepository _auditRepo;

    public BedrockAuditController(IAuditRepository auditRepo) => _auditRepo = auditRepo;

    [HttpGet]
    public async Task<ActionResult<BedrockResponse<AuditQueryResponse>>> Query(
        [FromQuery] Guid? userId,
        [FromQuery] AuditEventType? eventType,
        [FromQuery] DateTime? from,
        [FromQuery] DateTime? to,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50,
        CancellationToken ct = default)
    {
        if (pageSize > 200) pageSize = 200;

        var filter = new AuditQueryFilter(userId, eventType, from, to, page, pageSize);
        var result = await _auditRepo.QueryAsync(filter, ct);

        var items = result.Items
            .Select(e => new AuditEntryResponse(e.Id, e.EventType, e.IpAddress, e.UserAgent, e.UserId, e.OccurredAt))
            .ToList();

        return Ok(BedrockResponse<AuditQueryResponse>.Ok(new AuditQueryResponse(items, result.TotalCount)));
    }
}
