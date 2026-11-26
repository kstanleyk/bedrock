using Crestacle.Bedrock.Core.Entities;
using Crestacle.Bedrock.Core.Enumerations;
using Crestacle.Bedrock.Core.Interfaces.Repositories;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Sentinel.Core.DTOs;
using Crestacle.Sentinel.Core.Interfaces;
using FluentAssertions;
using NSubstitute;
using Xunit;

namespace Crestacle.Bedrock.Sentinel.Tests;

public sealed class SentinelProfileClaimsEnricherTests
{
    private static readonly Guid UserId = Guid.NewGuid();

    private static IBedrockClaimsEnricher BuildEnricher(IUserRepository users, ICredentialRepository credentials)
        => new SentinelProfileClaimsEnricher(users, credentials);

    private static IUserRepository UserWithName(string fullName, params string[] roleNames)
    {
        var repo  = Substitute.For<IUserRepository>();
        var roles = roleNames.Select(n => new RoleSummaryDto(Guid.NewGuid(), n, n, "Standard", null));
        var dto   = new UserDto(UserId, "identity-id", "user@example.com", fullName, null, roles);
        repo.GetByIdentityIdAsync(UserId.ToString(), Arg.Any<CancellationToken>()).Returns(dto);
        return repo;
    }

    private static IUserRepository NullUser()
    {
        var repo = Substitute.For<IUserRepository>();
        repo.GetByIdentityIdAsync(UserId.ToString(), Arg.Any<CancellationToken>()).Returns((UserDto?)null);
        return repo;
    }

    private static ICredentialRepository CredentialWithMfa(bool mfaEnabled)
    {
        var repo = Substitute.For<ICredentialRepository>();
        var cred = UserCredential.Create(UserId, "user@example.com", "hash");
        if (mfaEnabled) cred.EnableMfa(MfaMethod.Totp);
        repo.GetByUserIdAsync(UserId, Arg.Any<CancellationToken>()).Returns(cred);
        return repo;
    }

    private static ICredentialRepository NullCredential()
    {
        var repo = Substitute.For<ICredentialRepository>();
        repo.GetByUserIdAsync(UserId, Arg.Any<CancellationToken>()).Returns((UserCredential?)null);
        return repo;
    }

    [Fact]
    public async Task EnrichAsync_IncludesNameClaim()
    {
        var enricher = BuildEnricher(UserWithName("Jane Doe"), CredentialWithMfa(false));
        var claims   = await enricher.EnrichAsync(UserId);

        claims.Should().ContainKey("name").WhoseValue.Should().Be("Jane Doe");
    }

    [Fact]
    public async Task EnrichAsync_IncludesMfaEnabledTrue_WhenMfaIsOn()
    {
        var enricher = BuildEnricher(UserWithName("Jane"), CredentialWithMfa(true));
        var claims   = await enricher.EnrichAsync(UserId);

        claims.Should().ContainKey("mfa_enabled").WhoseValue.Should().Be("true");
    }

    [Fact]
    public async Task EnrichAsync_IncludesMfaEnabledFalse_WhenCredentialNotFound()
    {
        var enricher = BuildEnricher(UserWithName("Jane"), NullCredential());
        var claims   = await enricher.EnrichAsync(UserId);

        claims.Should().ContainKey("mfa_enabled").WhoseValue.Should().Be("false");
    }

    [Fact]
    public async Task EnrichAsync_IncludesEmptyName_WhenUserNotFound()
    {
        var enricher = BuildEnricher(NullUser(), NullCredential());
        var claims   = await enricher.EnrichAsync(UserId);

        claims.Should().ContainKey("name").WhoseValue.Should().BeEmpty();
    }

    [Fact]
    public async Task EnrichAsync_NeverAddsPermissionClaims()
    {
        // The whole point of this enricher: no Permission.* claims, regardless of what the
        // user is granted elsewhere -- that's SentinelClaimsEnricher's job, not this one's.
        var enricher = BuildEnricher(UserWithName("Bob"), CredentialWithMfa(false));
        var claims   = await enricher.EnrichAsync(UserId);

        claims.Keys.Should().BeEquivalentTo(new[] { "name", "mfa_enabled" });
    }

    [Fact]
    public async Task EnrichAsync_LooksUpTheUserByIdentityId_NotBySentinelsInternalId()
    {
        var sentinelInternalId = Guid.NewGuid();
        var repo = Substitute.For<IUserRepository>();
        var dto = new UserDto(sentinelInternalId, UserId.ToString(), "user@example.com", "Real Name", null, []);
        repo.GetByIdAsync(sentinelInternalId, Arg.Any<CancellationToken>()).Returns(dto);
        repo.GetByIdentityIdAsync(UserId.ToString(), Arg.Any<CancellationToken>()).Returns(dto);

        var enricher = BuildEnricher(repo, CredentialWithMfa(false));
        var claims = await enricher.EnrichAsync(UserId);

        claims["name"].Should().Be("Real Name");
        await repo.Received(1).GetByIdentityIdAsync(UserId.ToString(), Arg.Any<CancellationToken>());
        await repo.DidNotReceive().GetByIdAsync(UserId, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetRolesAsync_ReturnsRoleNamesFromUserRepository()
    {
        var enricher = BuildEnricher(UserWithName("Alice", "HR Manager", "Payroll Officer"), NullCredential());

        var roles = await enricher.GetRolesAsync(UserId);

        roles.Should().BeEquivalentTo(new[] { "HR Manager", "Payroll Officer" });
    }

    [Fact]
    public async Task GetRolesAsync_ReturnsEmpty_WhenUserNotFound()
    {
        var enricher = BuildEnricher(NullUser(), NullCredential());

        var roles = await enricher.GetRolesAsync(UserId);

        roles.Should().BeEmpty();
    }
}
