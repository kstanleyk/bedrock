using Crestacle.Sentinel.Core.DTOs;

namespace Crestacle.Sentinel.Core.Interfaces;

public interface IUserRepository
{
    Task<PagedResult<UserDto>> GetAllWithRolesAsync(
        int page = 1, int pageSize = 50, string? search = null, CancellationToken ct = default);

    /// <summary>Returns a single user with their active roles, or null if not found.</summary>
    Task<UserDto?> GetByIdAsync(Guid userId, CancellationToken ct = default);

    /// <summary>
    /// Returns a single user with their active roles, looked up by the external
    /// <c>IdentityId</c> (e.g. the consuming application's own user id, as a string) rather
    /// than Sentinel's internal primary key -- the two are architecturally distinct Guids.
    /// Callers that only have the external identity (e.g. a claims enricher called with the
    /// host application's own user id) must use this, not <see cref="GetByIdAsync"/>.
    /// </summary>
    Task<UserDto?> GetByIdentityIdAsync(string identityId, CancellationToken ct = default);

    /// <summary>Returns the external IdentityId for the given internal user ID, or null if not found.</summary>
    Task<string?> GetIdentityIdAsync(Guid userId, CancellationToken ct = default);

    /// <summary>
    /// Assigns the role to the user. When <paramref name="expiresOn"/> is provided the
    /// assignment is time-bound and will stop granting permissions after that UTC instant.
    /// </summary>
    /// <exception cref="Exceptions.SentinelNotFoundException">
    /// Thrown when <paramref name="roleId"/> does not exist, or belongs to a different tenant
    /// than the current <c>ITenantContext</c> and is not global/shared (<c>Role.TenantId == null</c>).
    /// </exception>
    Task AddRoleAsync(Guid userId, Guid roleId, DateTime? expiresOn = null, CancellationToken ct = default);

    Task RemoveRoleAsync(Guid userId, Guid roleId, CancellationToken ct = default);
}
