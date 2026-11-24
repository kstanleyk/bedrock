using System.Security.Claims;
using Crestacle.Bedrock.Core.Exceptions;
using Crestacle.Bedrock.Core.Interfaces;
using Crestacle.Bedrock.Core.Interfaces.Repositories;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;

namespace Crestacle.Bedrock.AspNetCore.Authorization;

/// <summary>
/// Requires a valid, single-use step-up JWT in the <c>X-Step-Up-Token</c> header.
/// On the first use of the JWT on a protected endpoint the challenge is marked used;
/// subsequent calls with the same JWT receive 403.
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = false)]
public sealed class RequiresStepUpAttribute : Attribute, IAsyncAuthorizationFilter
{
    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        var userId = GetUserId(context);
        if (userId is null)
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        var stepUpToken = context.HttpContext.Request.Headers["X-Step-Up-Token"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(stepUpToken))
        {
            context.Result = new ObjectResult(new { error = "Step-up authentication required." })
                { StatusCode = StatusCodes.Status403Forbidden };
            return;
        }

        var tokenService = context.HttpContext.RequestServices.GetRequiredService<ITokenService>();
        var (isValid, challengeId) = tokenService.ValidateAndExtractStepUp(stepUpToken, userId.Value);

        if (!isValid || challengeId is null)
        {
            context.Result = new ObjectResult(new { error = "Invalid or expired step-up token." })
                { StatusCode = StatusCodes.Status403Forbidden };
            return;
        }

        var challengeRepo = context.HttpContext.RequestServices.GetRequiredService<IStepUpChallengeRepository>();
        var unitOfWork = context.HttpContext.RequestServices.GetRequiredService<IBedrockUnitOfWork>();

        var challenge = await challengeRepo.GetByIdAsync(challengeId.Value);
        if (challenge is null || challenge.UsedAt is not null)
        {
            context.Result = new ObjectResult(new { error = "Step-up token has already been used." })
                { StatusCode = StatusCodes.Status403Forbidden };
            return;
        }

        challenge.MarkUsed();
        await challengeRepo.UpdateAsync(challenge);

        try
        {
            await unitOfWork.SaveChangesAsync();
        }
        catch (BedrockConcurrencyException)
        {
            // Two parallel requests presenting the same step-up JWT can both load the
            // challenge (separate per-request DbContexts) before either save commits, both
            // pass the UsedAt-is-null check above, and both call MarkUsed(). RowVersion makes
            // the loser's save fail here instead of silently marking the challenge used twice --
            // surfaced identically to an already-used token, since that is exactly what this is
            // from the caller's perspective.
            context.Result = new ObjectResult(new { error = "Step-up token has already been used." })
                { StatusCode = StatusCodes.Status403Forbidden };
        }
    }

    private static Guid? GetUserId(AuthorizationFilterContext context)
    {
        var raw = context.HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
        return Guid.TryParse(raw, out var id) ? id : null;
    }
}
