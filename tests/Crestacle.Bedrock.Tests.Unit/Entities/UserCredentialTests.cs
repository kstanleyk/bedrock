using Crestacle.Bedrock.Core.Entities;
using FluentAssertions;
using Xunit;

namespace Crestacle.Bedrock.Tests.Unit.Entities;

public sealed class UserCredentialTests
{
    private static UserCredential CreateCredential()
        => UserCredential.Create(Guid.NewGuid(), "user@example.com", "hash");

    [Fact]
    public void AdminLock_SetsIsAdminLockedFlag_AlongsideTheLockoutEndSentinel()
    {
        var credential = CreateCredential();

        credential.AdminLock();

        credential.IsAdminLocked.Should().BeTrue();
        credential.IsLockedOut().Should().BeTrue();
        credential.LockoutEnd.Should().NotBeNull();
        credential.LockoutEnd!.Value.Should().BeAfter(DateTime.UtcNow.AddYears(50));
    }

    [Fact]
    public void AdminUnlock_ClearsIsAdminLockedFlag_AlongsideTheLockoutEnd()
    {
        var credential = CreateCredential();
        credential.AdminLock();

        credential.AdminUnlock();

        credential.IsAdminLocked.Should().BeFalse();
        credential.IsLockedOut().Should().BeFalse();
        credential.LockoutEnd.Should().BeNull();
    }

    [Fact]
    public void RecordFailedLogin_TimedLockout_DoesNotSetIsAdminLocked()
    {
        var credential = CreateCredential();

        for (var i = 0; i < 5; i++)
            credential.RecordFailedLogin(maxAttempts: 5, lockoutDuration: TimeSpan.FromMinutes(15));

        credential.IsLockedOut().Should().BeTrue();
        credential.IsAdminLocked.Should().BeFalse();
    }

    [Fact]
    public void RecordSuccessfulLogin_ClearsIsAdminLocked_AsDefenseInDepth()
    {
        var credential = CreateCredential();
        credential.AdminLock();

        credential.RecordSuccessfulLogin();

        credential.IsAdminLocked.Should().BeFalse();
        credential.LockoutEnd.Should().BeNull();
    }
}
