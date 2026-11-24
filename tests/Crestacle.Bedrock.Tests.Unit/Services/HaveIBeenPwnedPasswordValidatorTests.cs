using System.Net;
using System.Security.Cryptography;
using System.Text;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.HaveIBeenPwned;
using FluentAssertions;
using NSubstitute;
using Xunit;

namespace Crestacle.Bedrock.Tests.Unit.Services;

public sealed class HaveIBeenPwnedPasswordValidatorTests
{
    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static string Sha1Hex(string password)
    {
        var bytes = SHA1.HashData(Encoding.UTF8.GetBytes(password));
        return Convert.ToHexString(bytes);
    }

    /// <summary>Builds a validator whose HIBP client returns <paramref name="responseBody"/>.</summary>
    private static HaveIBeenPwnedPasswordValidator BuildWithResponse(string responseBody)
    {
        var handler = new StubHandler(HttpStatusCode.OK, responseBody);
        return Build(handler);
    }

    /// <summary>Builds a validator whose HIBP client throws <paramref name="exception"/>.</summary>
    private static HaveIBeenPwnedPasswordValidator BuildWithException(Exception exception)
    {
        var handler = new ThrowingHandler(exception);
        return Build(handler);
    }

    private static HaveIBeenPwnedPasswordValidator Build(HttpMessageHandler handler)
    {
        var httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://api.pwnedpasswords.com"),
            Timeout = TimeSpan.FromSeconds(3),
        };

        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient("hibp").Returns(httpClient);

        // Inner validator always passes so tests focus purely on HIBP behaviour.
        var inner = new AlwaysValidPasswordValidator();

        return new HaveIBeenPwnedPasswordValidator(factory, inner);
    }

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    [Fact]
    public async Task IsValid_BreachedPassword_ReturnsFalseWithBreachMessage()
    {
        var suffix = Sha1Hex("password")[5..];
        // The HIBP range response contains our suffix with a hit count.
        var body = $"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\r\n{suffix}:9876543\r\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:2\r\n";
        var validator = BuildWithResponse(body);

        var (valid, errors) = await validator.IsValidAsync("password");

        valid.Should().BeFalse();
        errors.Should().ContainSingle()
            .Which.Should().Be(
                "This password has appeared in a known data breach. Please choose a different password.");
    }

    [Fact]
    public async Task IsValid_UnknownPassword_ReturnsTrue()
    {
        // Response contains entries for other passwords — our suffix is absent.
        const string body = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\r\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:2\r\n";
        var validator = BuildWithResponse(body);

        var (valid, errors) = await validator.IsValidAsync("SuperSecure!X9y@2024");

        valid.Should().BeTrue();
        errors.Should().BeEmpty();
    }

    [Fact]
    public async Task IsValid_HttpFailure_ReturnsTrueFailOpen()
    {
        // Network error must never block a registration attempt.
        var validator = BuildWithException(new HttpRequestException("Simulated network failure"));

        var (valid, errors) = await validator.IsValidAsync("AnyPassword1!");

        valid.Should().BeTrue();
        errors.Should().BeEmpty();
    }

    [Fact]
    public async Task IsPreviouslyUsed_DelegatesToInner()
    {
        var innerSub = Substitute.For<IPasswordValidator>();
        innerSub.IsPreviouslyUsedAsync("pw", Arg.Any<IEnumerable<string>>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(true));

        var httpClient = new HttpClient(new StubHandler(HttpStatusCode.OK, string.Empty))
        {
            BaseAddress = new Uri("https://api.pwnedpasswords.com"),
        };
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient("hibp").Returns(httpClient);

        var validator = new HaveIBeenPwnedPasswordValidator(factory, innerSub);

        (await validator.IsPreviouslyUsedAsync("pw", [])).Should().BeTrue();
    }

    // -------------------------------------------------------------------------
    // HTTP stubs
    // -------------------------------------------------------------------------

    private sealed class StubHandler(HttpStatusCode status, string body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(status)
            {
                Content = new StringContent(body),
            };
            return Task.FromResult(response);
        }
    }

    private sealed class ThrowingHandler(Exception exception) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromException<HttpResponseMessage>(exception);
    }

    // -------------------------------------------------------------------------
    // Inner-validator stub
    // -------------------------------------------------------------------------

    private sealed class AlwaysValidPasswordValidator : IPasswordValidator
    {
        public Task<(bool IsValid, IReadOnlyList<string> Errors)> IsValidAsync(string password, CancellationToken ct = default)
            => Task.FromResult<(bool, IReadOnlyList<string>)>((true, []));

        public Task<bool> IsPreviouslyUsedAsync(string password, IEnumerable<string> hashes, CancellationToken ct = default)
            => Task.FromResult(false);
    }
}
