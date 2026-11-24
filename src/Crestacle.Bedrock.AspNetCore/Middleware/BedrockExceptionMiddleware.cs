using System.Text.Json;
using Crestacle.Bedrock.Core;
using Crestacle.Bedrock.Core.DTOs;
using Crestacle.Bedrock.Core.Exceptions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Crestacle.Bedrock.AspNetCore.Middleware;

public sealed class BedrockExceptionMiddleware
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly RequestDelegate _next;
    private readonly ILogger<BedrockExceptionMiddleware> _logger;

    public BedrockExceptionMiddleware(RequestDelegate next, ILogger<BedrockExceptionMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (BedrockValidationException ex)
        {
            await WriteAsync(context, StatusCodes.Status400BadRequest, ex.Code, ex.Errors);
        }
        catch (BedrockForbiddenException ex)
        {
            await WriteAsync(context, StatusCodes.Status403Forbidden, ex.Code, ex.Message);
        }
        catch (BedrockNotFoundException ex)
        {
            await WriteAsync(context, StatusCodes.Status404NotFound, ex.Code, ex.Message);
        }
        catch (BedrockConcurrencyException ex)
        {
            await WriteAsync(context, StatusCodes.Status409Conflict, ex.Code, ex.Message);
        }
        catch (BedrockAccountLockedException ex)
        {
            BedrockTelemetry.AccountLockouts.Add(1);
            var retryAfter = Math.Max(0, (int)(ex.LockoutEnd - DateTime.UtcNow).TotalSeconds);
            context.Response.Headers["Retry-After"] = retryAfter.ToString();
            await WriteAsync(context, StatusCodes.Status423Locked, ex.Code, ex.Message);
        }
        catch (BedrockIpRateLimitException ex)
        {
            BedrockTelemetry.IpRateLimitTrips.Add(1);
            context.Response.Headers["Retry-After"] = ((int)ex.RetryAfter.TotalSeconds).ToString();
            await WriteAsync(context, StatusCodes.Status429TooManyRequests, ex.Code, ex.Message);
        }
        catch (BedrockRateLimitException ex)
        {
            BedrockTelemetry.OtpRateLimitTrips.Add(1);
            context.Response.Headers["Retry-After"] = ((int)ex.RetryAfter.TotalSeconds).ToString();
            await WriteAsync(context, StatusCodes.Status429TooManyRequests, ex.Code, ex.Message);
        }
        catch (BedrockException bex)
        {
            _logger.LogWarning(bex, "Unhandled BedrockException");
            await WriteAsync(context, StatusCodes.Status400BadRequest, bex.Code, bex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled exception. TraceIdentifier: {TraceIdentifier}", context.TraceIdentifier);
            await WriteAsync(
                context,
                StatusCodes.Status500InternalServerError,
                BedrockErrorCodes.InternalError,
                $"An unexpected error occurred. Reference: {context.TraceIdentifier}");
        }
    }

    private static Task WriteAsync(HttpContext context, int statusCode, string? code, string message)
        => WriteAsync(context, statusCode, code, [message]);

    private static Task WriteAsync(HttpContext context, int statusCode, string? code, IReadOnlyList<string> errors)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/json";
        var response = code is null
            ? BedrockResponse.Fail([.. errors])
            : new BedrockResponse { Success = false, Code = code, Errors = errors };
        return context.Response.WriteAsync(JsonSerializer.Serialize(response, JsonOptions));
    }
}
