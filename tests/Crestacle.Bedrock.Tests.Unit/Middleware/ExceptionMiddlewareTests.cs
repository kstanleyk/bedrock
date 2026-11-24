using System.Text;
using System.Text.Json;
using Crestacle.Bedrock.AspNetCore.Middleware;
using Crestacle.Bedrock.Core;
using Crestacle.Bedrock.Core.DTOs;
using Crestacle.Bedrock.Core.Exceptions;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Crestacle.Bedrock.Tests.Unit.Middleware;

public sealed class ExceptionMiddlewareTests
{
    private static async Task<(HttpContext Context, BedrockResponse Body)> InvokeAsync(RequestDelegate next)
    {
        var middleware = new BedrockExceptionMiddleware(next, NullLogger<BedrockExceptionMiddleware>.Instance);

        var context = new DefaultHttpContext();
        context.TraceIdentifier = "trace-12345";
        context.Response.Body = new MemoryStream();

        await middleware.InvokeAsync(context);

        context.Response.Body.Seek(0, SeekOrigin.Begin);
        var raw = await new StreamReader(context.Response.Body, Encoding.UTF8).ReadToEndAsync();
        var body = JsonSerializer.Deserialize<BedrockResponse>(raw, new JsonSerializerOptions(JsonSerializerDefaults.Web))!;

        return (context, body);
    }

    [Fact]
    public async Task InvokeAsync_NonBedrockException_Returns500WithNoLeakedMessage()
    {
        const string secretMessage = "connection string password=S3cr3t!; leaked internal detail";

        var (context, body) = await InvokeAsync(_ => throw new InvalidOperationException(secretMessage));

        context.Response.StatusCode.Should().Be(StatusCodes.Status500InternalServerError);
        body.Success.Should().BeFalse();
        body.Code.Should().Be(BedrockErrorCodes.InternalError);
        body.Errors.Should().NotBeEmpty();
        body.Errors.Should().NotContain(e => e.Contains(secretMessage));
        body.Errors.Should().NotContain(e => e.Contains("InvalidOperationException"));
        body.Errors.Should().NotContain(e => e.Contains("StackTrace", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task InvokeAsync_NonBedrockException_IncludesCorrelationId()
    {
        var (_, body) = await InvokeAsync(_ => throw new InvalidOperationException("boom"));

        body.Errors.Should().ContainSingle(e => e.Contains("trace-12345"));
    }

    [Fact]
    public async Task InvokeAsync_BedrockException_StillHandledAsBefore()
    {
        var (context, body) = await InvokeAsync(_ => throw new BedrockForbiddenException("nope"));

        context.Response.StatusCode.Should().Be(StatusCodes.Status403Forbidden);
        body.Success.Should().BeFalse();
        body.Code.Should().Be(BedrockErrorCodes.Forbidden);
        body.Errors.Should().ContainSingle(e => e == "nope");
    }
}
