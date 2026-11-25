using Crestacle.Bedrock.AspNetCore.Services;
using Crestacle.Bedrock.Core.Options;
using FluentAssertions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Xunit;
using IPasswordHasher = Crestacle.Bedrock.Core.Interfaces.Services.IPasswordHasher;

namespace Crestacle.Bedrock.Tests.Unit.Services;

public sealed class DefaultPasswordValidatorTests
{
    private static DefaultPasswordValidator BuildValidator(PasswordOptions? opts = null)
    {
        var options = new BedrockOptions { Password = opts ?? new PasswordOptions() };
        var wrapped = Options.Create(options);
        var hasher = new Argon2idPasswordHasher();
        var commonValidator = new CommonPasswordValidator(wrapped);
        return new DefaultPasswordValidator(wrapped, hasher, commonValidator);
    }

    [Fact]
    public async Task IsValid_StrongPassword_ReturnsTrue()
    {
        var validator = BuildValidator();
        var (valid, errors) = await validator.IsValidAsync("StrongP@ssw0rd!");
        valid.Should().BeTrue();
        errors.Should().BeEmpty();
    }

    [Fact]
    public async Task IsValid_TooShort_ReturnsFalse()
    {
        var validator = BuildValidator(new PasswordOptions { MinLength = 12 });
        var (valid, errors) = await validator.IsValidAsync("Short1!");
        valid.Should().BeFalse();
        errors.Should().ContainSingle(e => e.Contains("12 characters"));
    }

    [Fact]
    public async Task IsValid_NoUppercase_ReturnsFalse()
    {
        var validator = BuildValidator();
        var (valid, errors) = await validator.IsValidAsync("nouppercase1!");
        valid.Should().BeFalse();
        errors.Should().ContainSingle(e => e.Contains("uppercase"));
    }

    [Fact]
    public async Task IsValid_NoLowercase_ReturnsFalse()
    {
        var validator = BuildValidator();
        var (valid, errors) = await validator.IsValidAsync("NOLOWERCASE1!");
        valid.Should().BeFalse();
        errors.Should().ContainSingle(e => e.Contains("lowercase"));
    }

    [Fact]
    public async Task IsValid_NoDigit_ReturnsFalse()
    {
        var validator = BuildValidator();
        var (valid, errors) = await validator.IsValidAsync("NoDigitPass!");
        valid.Should().BeFalse();
        errors.Should().ContainSingle(e => e.Contains("digit"));
    }

    [Fact]
    public async Task IsValid_NoSpecialChar_ReturnsFalse()
    {
        var validator = BuildValidator();
        var (valid, errors) = await validator.IsValidAsync("NoSpecialChar1");
        valid.Should().BeFalse();
        errors.Should().ContainSingle(e => e.Contains("special"));
    }

    [Fact]
    public async Task IsValid_MultipleViolations_ReportsAll()
    {
        var validator = BuildValidator();
        var (valid, errors) = await validator.IsValidAsync("short");
        valid.Should().BeFalse();
        errors.Count.Should().BeGreaterThan(1);
    }

    [Fact]
    public async Task IsPreviouslyUsed_MatchingHash_ReturnsTrue()
    {
        var hasher = new Argon2idPasswordHasher();
        var hash = hasher.Hash("Password1!");
        var validator = BuildValidator();
        (await validator.IsPreviouslyUsedAsync("Password1!", [hash])).Should().BeTrue();
    }

    [Fact]
    public async Task IsPreviouslyUsed_NoMatch_ReturnsFalse()
    {
        var hasher = new Argon2idPasswordHasher();
        var hash = hasher.Hash("DifferentP@ss1");
        var validator = BuildValidator();
        (await validator.IsPreviouslyUsedAsync("Password1!", [hash])).Should().BeFalse();
    }

    [Fact]
    public async Task IsPreviouslyUsed_EmptyHistory_ReturnsFalse()
    {
        var validator = BuildValidator();
        (await validator.IsPreviouslyUsedAsync("Password1!", [])).Should().BeFalse();
    }
}
