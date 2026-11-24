using Crestacle.Bedrock.AspNetCore;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.HaveIBeenPwned;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Crestacle.Bedrock.Tests.Unit.Extensions;

public sealed class HaveIBeenPwnedExtensionsTests
{
    // -------------------------------------------------------------------------
    // WithHaveIBeenPwnedPasswordValidator must wrap whatever IPasswordValidator
    // is already registered rather than silently discarding it in favor of a
    // hardcoded DefaultPasswordValidator.
    // -------------------------------------------------------------------------

    [Fact]
    public async Task WithHaveIBeenPwnedPasswordValidator_InstanceRegistration_PreservesCustomValidatorAsInner()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IPasswordValidator>(new SentinelPasswordValidator());
        var builder = new BedrockBuilder(services);

        builder.WithHaveIBeenPwnedPasswordValidator();

        using var provider = services.BuildServiceProvider();
        var resolved = provider.GetRequiredService<IPasswordValidator>();

        resolved.Should().BeOfType<HaveIBeenPwnedPasswordValidator>();

        var (valid, errors) = await resolved.IsValidAsync("irrelevant");

        valid.Should().BeFalse("the custom validator's own rule must still run");
        errors.Should().ContainSingle().Which.Should().Be(SentinelPasswordValidator.SentinelError);
    }

    [Fact]
    public async Task WithHaveIBeenPwnedPasswordValidator_FactoryRegistration_PreservesCustomValidatorAsInner()
    {
        var services = new ServiceCollection();
        services.AddScoped<IPasswordValidator>(_ => new SentinelPasswordValidator());
        var builder = new BedrockBuilder(services);

        builder.WithHaveIBeenPwnedPasswordValidator();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var resolved = scope.ServiceProvider.GetRequiredService<IPasswordValidator>();

        var (valid, errors) = await resolved.IsValidAsync("irrelevant");

        valid.Should().BeFalse("a factory-registered custom validator must still run, not be replaced");
        errors.Should().ContainSingle().Which.Should().Be(SentinelPasswordValidator.SentinelError);
    }

    [Fact]
    public async Task WithHaveIBeenPwnedPasswordValidator_CustomValidator_IsPreviouslyUsedStillDelegatesToIt()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IPasswordValidator>(new SentinelPasswordValidator());
        var builder = new BedrockBuilder(services);

        builder.WithHaveIBeenPwnedPasswordValidator();

        using var provider = services.BuildServiceProvider();
        var resolved = provider.GetRequiredService<IPasswordValidator>();

        (await resolved.IsPreviouslyUsedAsync("irrelevant", [])).Should().BeTrue(
            "IsPreviouslyUsed must still be answered by the caller's own custom validator");
    }

    // -------------------------------------------------------------------------
    // A distinctive always-false validator used to prove the real registered
    // instance -- not Bedrock's DefaultPasswordValidator -- is the one actually
    // consulted.
    // -------------------------------------------------------------------------

    private sealed class SentinelPasswordValidator : IPasswordValidator
    {
        public const string SentinelError = "SENTINEL-CUSTOM-RULE-REJECTED";

        public Task<(bool IsValid, IReadOnlyList<string> Errors)> IsValidAsync(string password, CancellationToken ct = default)
            => Task.FromResult<(bool, IReadOnlyList<string>)>((false, [SentinelError]));

        public Task<bool> IsPreviouslyUsedAsync(string password, IEnumerable<string> hashes, CancellationToken ct = default)
            => Task.FromResult(true);
    }
}
