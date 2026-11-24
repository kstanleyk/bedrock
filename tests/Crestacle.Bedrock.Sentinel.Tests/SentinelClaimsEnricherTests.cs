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

public sealed class SentinelClaimsEnricherTests
{
    private static readonly Guid UserId = Guid.NewGuid();

    private static IBedrockClaimsEnricher BuildEnricher(
        IUserPermissionRepository permissions,
        IUserRepository users,
        ICredentialRepository credentials)
        => new SentinelClaimsEnricher(permissions, users, credentials);

    private static IUserPermissionRepository NoPermissions()
    {
        var repo = Substitute.For<IUserPermissionRepository>();
        repo.GetPermissionsForUserAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new HashSet<string>()));
        return repo;
    }

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
    public async Task EnrichAsync_ReturnsTrueEntryPerPermission()
    {
        var permissions = Substitute.For<IUserPermissionRepository>();
        permissions.GetPermissionsForUserAsync(UserId.ToString(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new HashSet<string> { "Permission.Users.Read", "Permission.Reports.Read" }));

        var enricher = BuildEnricher(permissions, UserWithName("Alice"), CredentialWithMfa(false));
        var claims   = await enricher.EnrichAsync(UserId);

        claims.Should().ContainKey("Permission.Users.Read").WhoseValue.Should().Be("true");
        claims.Should().ContainKey("Permission.Reports.Read").WhoseValue.Should().Be("true");
    }

    [Fact]
    public async Task EnrichAsync_IncludesNameClaim()
    {
        var enricher = BuildEnricher(NoPermissions(), UserWithName("Jane Doe"), CredentialWithMfa(false));
        var claims   = await enricher.EnrichAsync(UserId);

        claims.Should().ContainKey("name").WhoseValue.Should().Be("Jane Doe");
    }

    [Fact]
    public async Task EnrichAsync_IncludesMfaEnabledTrue_WhenMfaIsOn()
    {
        var enricher = BuildEnricher(NoPermissions(), UserWithName("Jane"), CredentialWithMfa(true));
        var claims   = await enricher.EnrichAsync(UserId);

        claims.Should().ContainKey("mfa_enabled").WhoseValue.Should().Be("true");
    }

    [Fact]
    public async Task EnrichAsync_IncludesMfaEnabledFalse_WhenMfaIsOff()
    {
        var enricher = BuildEnricher(NoPermissions(), UserWithName("Jane"), CredentialWithMfa(false));
        var claims   = await enricher.EnrichAsync(UserId);

        claims.Should().ContainKey("mfa_enabled").WhoseValue.Should().Be("false");
    }

    [Fact]
    public async Task EnrichAsync_IncludesMfaEnabledFalse_WhenCredentialNotFound()
    {
        var enricher = BuildEnricher(NoPermissions(), UserWithName("Jane"), NullCredential());
        var claims   = await enricher.EnrichAsync(UserId);

        claims.Should().ContainKey("mfa_enabled").WhoseValue.Should().Be("false");
    }

    [Fact]
    public async Task EnrichAsync_IncludesEmptyName_WhenUserNotFound()
    {
        var enricher = BuildEnricher(NoPermissions(), NullUser(), NullCredential());
        var claims   = await enricher.EnrichAsync(UserId);

        claims.Should().ContainKey("name").WhoseValue.Should().BeEmpty();
    }

    [Fact]
    public async Task EnrichAsync_ReturnsOnlyMetaClaims_WhenNoPermissionsGranted()
    {
        var enricher = BuildEnricher(NoPermissions(), UserWithName("Bob"), CredentialWithMfa(false));
        var claims   = await enricher.EnrichAsync(UserId);

        claims.Keys.Should().BeEquivalentTo(new[] { "name", "mfa_enabled" });
    }

    [Fact]
    public async Task EnrichAsync_LooksUpTheUserByIdentityId_NotBySentinelsInternalId()
    {
        // userId here is Bedrock's own internal id; Sentinel's User.Id is a SEPARATE,
        // independently generated Guid -- modeled here as sentinelInternalId, deliberately
        // different from UserId, exactly like a real deployment. GetByIdAsync (keyed on
        // Sentinel's internal id) is mocked to return the real user ONLY for that different
        // Guid, never for UserId -- so a correct EnrichAsync, which only has Bedrock's UserId
        // to work with, can only find this user via GetByIdentityIdAsync(UserId.ToString()).
        var sentinelInternalId = Guid.NewGuid();
        var repo = Substitute.For<IUserRepository>();
        var dto = new UserDto(sentinelInternalId, UserId.ToString(), "user@example.com", "Real Name", null, []);
        repo.GetByIdAsync(sentinelInternalId, Arg.Any<CancellationToken>()).Returns(dto);
        repo.GetByIdentityIdAsync(UserId.ToString(), Arg.Any<CancellationToken>()).Returns(dto);
        // repo.GetByIdAsync(UserId, ...) intentionally left unconfigured -> NSubstitute default:
        // null -- the wrong lookup (what the pre-fix code called) must find nothing.

        var enricher = BuildEnricher(NoPermissions(), repo, CredentialWithMfa(false));
        var claims = await enricher.EnrichAsync(UserId);

        claims["name"].Should().Be("Real Name",
            "EnrichAsync must call GetByIdentityIdAsync(userId.ToString()), not " +
            "GetByIdAsync(userId) -- Sentinel's internal User.Id is architecturally distinct " +
            "from Bedrock's own user id, so the wrong-method lookup can never find this user " +
            "in a real deployment either");

        await repo.Received(1).GetByIdentityIdAsync(UserId.ToString(), Arg.Any<CancellationToken>());
        await repo.DidNotReceive().GetByIdAsync(UserId, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task EnrichAsync_PassesUserIdAsStringToPermissionRepository()
    {
        var permissions = Substitute.For<IUserPermissionRepository>();
        permissions.GetPermissionsForUserAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new HashSet<string>()));

        var enricher = BuildEnricher(permissions, UserWithName("Bob"), CredentialWithMfa(false));
        await enricher.EnrichAsync(UserId);

        await permissions.Received(1).GetPermissionsForUserAsync(UserId.ToString(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetRolesAsync_ReturnsRoleNamesFromUserRepository()
    {
        var enricher = BuildEnricher(NoPermissions(), UserWithName("Alice", "HR Manager", "Payroll Officer"), NullCredential());

        var roles = await enricher.GetRolesAsync(UserId);

        roles.Should().BeEquivalentTo(new[] { "HR Manager", "Payroll Officer" });
    }

    [Fact]
    public async Task GetRolesAsync_ReturnsEmpty_WhenUserNotFound()
    {
        var enricher = BuildEnricher(NoPermissions(), NullUser(), NullCredential());

        var roles = await enricher.GetRolesAsync(UserId);

        roles.Should().BeEmpty();
    }
}
