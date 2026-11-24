using System.Net;
using System.Net.Http.Json;
using Crestacle.Sentinel.Core.DTOs;
using Crestacle.Sentinel.Core.Entities;
using Crestacle.Sentinel.Core.Enums;

namespace Crestacle.Sentinel.Tests.Controllers;

/// <summary>
/// Integration tests for the HTTP security layer — verifies that every security
/// guard is enforced at the controller boundary, not just in repositories.
/// Each test spins up a full in-process TestServer with mocked repositories.
/// </summary>
public sealed class SecurityBoundaryTests
{
    // ── Permission name shorthands ────────────────────────────────────────────

    private const string UserRead   = "Permission.User.Read";
    private const string UserUpdate = "Permission.User.Update";
    private const string RoleRead   = "Permission.Role.Read";
    private const string RoleUpdate = "Permission.Role.Update";
    private const string AuditRead  = "Permission.Audit.Read";

    // ── 401 — Unauthenticated ─────────────────────────────────────────────────

    [Theory]
    [InlineData("GET",  "/api/auth/users")]
    [InlineData("GET",  "/api/auth/roles")]
    [InlineData("GET",  "/api/auth/audit")]
    [InlineData("GET",  "/api/auth/pending-assignments")]
    [InlineData("GET",  "/api/auth/permissions/me")]
    public async Task Unauthenticated_ProtectedEndpoint_Returns401(string method, string path)
    {
        using var host   = SentinelTestHost.Create();
        using var client = host.CreateClient(); // no subject → anonymous

        var response = await client.SendAsync(new HttpRequestMessage(new HttpMethod(method), path));

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            $"anonymous requests to {path} must be rejected");
    }

    // ── 403 — Missing permission ──────────────────────────────────────────────

    [Theory]
    [InlineData("/api/auth/users",               UserRead)]
    [InlineData("/api/auth/roles",               RoleRead)]
    [InlineData("/api/auth/audit",               AuditRead)]
    [InlineData("/api/auth/pending-assignments", UserRead)]
    public async Task Authenticated_MissingPermission_Returns403(string path, string required)
    {
        using var host   = SentinelTestHost.Create();
        using var client = host.CreateClient("user-1"); // authenticated but no permissions

        var response = await client.GetAsync(path);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden,
            $"'{required}' is required for GET {path}");
    }

    // ── 200 — Authenticated with correct permission ───────────────────────────

    [Theory]
    [InlineData("/api/auth/users",               UserRead)]
    [InlineData("/api/auth/roles",               RoleRead)]
    [InlineData("/api/auth/audit",               AuditRead)]
    [InlineData("/api/auth/pending-assignments", UserRead)]
    public async Task Authenticated_WithPermission_Returns200(string path, string permission)
    {
        using var host   = SentinelTestHost.Create();
        using var client = host.CreateClient("user-1", permission);

        var response = await client.GetAsync(path);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ── 400 — Invalid pagination ──────────────────────────────────────────────

    [Theory]
    [InlineData(0,   50)] // page < 1
    [InlineData(1,    0)] // pageSize < 1
    [InlineData(1,  201)] // pageSize > 200
    public async Task GetUsers_InvalidPagination_Returns400(int page, int pageSize)
    {
        using var host   = SentinelTestHost.Create();
        using var client = host.CreateClient("admin", UserRead);

        var response = await client.GetAsync($"/api/auth/users?page={page}&pageSize={pageSize}");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Theory]
    [InlineData(0,   50)]
    [InlineData(1,    0)]
    [InlineData(1,  201)]
    public async Task GetRoles_InvalidPagination_Returns400(int page, int pageSize)
    {
        using var host   = SentinelTestHost.Create();
        using var client = host.CreateClient("admin", RoleRead);

        var response = await client.GetAsync($"/api/auth/roles?page={page}&pageSize={pageSize}");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    // ── 400 — Input validation ────────────────────────────────────────────────

    [Fact]
    public async Task AssignPermission_EmptyPermissionId_Returns400()
    {
        using var host   = SentinelTestHost.Create();
        using var client = host.CreateClient("admin", RoleUpdate, "Permission.Invoice.Read");

        var body     = JsonContent.Create(new { permissionId = "" });
        var response = await client.PostAsync($"/api/auth/roles/{Guid.NewGuid()}/permissions", body);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task AssignRole_EmptyRoleId_Returns400()
    {
        using var host   = SentinelTestHost.Create();
        using var client = host.CreateClient("admin", UserUpdate);

        var body     = JsonContent.Create(new { roleId = Guid.Empty });
        var response = await client.PostAsync($"/api/auth/users/{Guid.NewGuid()}/roles", body);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task AssignRole_PastExpiresOn_Returns400()
    {
        using var host   = SentinelTestHost.Create();
        using var client = host.CreateClient("admin", UserUpdate);

        var body = JsonContent.Create(new
        {
            roleId    = Guid.NewGuid(),
            expiresOn = DateTime.UtcNow.AddDays(-1),
        });
        var response = await client.PostAsync($"/api/auth/users/{Guid.NewGuid()}/roles", body);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest,
            "expiresOn must be a future date");
    }

    // ── 403 — Self-modification guard ─────────────────────────────────────────

    [Fact]
    public async Task AssignRole_SelfModification_Returns403()
    {
        using var host = SentinelTestHost.Create();
        var userId     = Guid.NewGuid();

        // Target user's external identity matches the acting user's subject.
        host.UserRepo.GetIdentityIdAsync(userId, Arg.Any<CancellationToken>())
                     .Returns("actor-1");

        using var client = host.CreateClient("actor-1", UserUpdate);
        var body         = JsonContent.Create(new { roleId = Guid.NewGuid() });
        var response     = await client.PostAsync($"/api/auth/users/{userId}/roles", body);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden,
            "an actor must not modify their own role assignments");
    }

    [Fact]
    public async Task RemoveRole_SelfModification_Returns403()
    {
        using var host = SentinelTestHost.Create();
        var userId     = Guid.NewGuid();

        host.UserRepo.GetIdentityIdAsync(userId, Arg.Any<CancellationToken>())
                     .Returns("actor-1");

        using var client = host.CreateClient("actor-1", UserUpdate);
        var response     = await client.DeleteAsync(
            $"/api/auth/users/{userId}/roles/{Guid.NewGuid()}");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    // ── 403 — Internal role guard ─────────────────────────────────────────────

    [Fact]
    public async Task AssignPermission_InternalRole_Returns403()
    {
        using var host = SentinelTestHost.Create();
        var roleId     = Guid.NewGuid();

        host.RoleRepo.GetRoleTypeAsync(roleId, Arg.Any<CancellationToken>())
                     .Returns((RoleType?)RoleType.Internal);

        using var client = host.CreateClient("admin", RoleUpdate, "Permission.Invoice.Read");
        var body         = JsonContent.Create(new { permissionId = "Permission.Invoice.Read" });
        var response     = await client.PostAsync($"/api/auth/roles/{roleId}/permissions", body);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden,
            "Internal roles are immutable via the API");
    }

    [Fact]
    public async Task RemovePermission_InternalRole_Returns403()
    {
        using var host = SentinelTestHost.Create();
        var roleId     = Guid.NewGuid();

        host.RoleRepo.GetRoleTypeAsync(roleId, Arg.Any<CancellationToken>())
                     .Returns((RoleType?)RoleType.Internal);

        using var client = host.CreateClient("admin", RoleUpdate);
        var response     = await client.DeleteAsync(
            $"/api/auth/roles/{roleId}/permissions/Permission.Invoice.Read");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    // ── 403 — Privilege-escalation guard ─────────────────────────────────────

    [Fact]
    public async Task AssignPermission_ActorLacksTargetPermission_Returns403()
    {
        using var host = SentinelTestHost.Create();
        // Actor has Role.Update but NOT Invoice.Create — cannot grant what they don't hold.
        using var client = host.CreateClient("admin", RoleUpdate);

        var body     = JsonContent.Create(new { permissionId = "Permission.Invoice.Create" });
        var response = await client.PostAsync($"/api/auth/roles/{Guid.NewGuid()}/permissions", body);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden,
            "an actor cannot grant a permission they do not themselves hold");
    }

    [Fact]
    public async Task AssignPermission_ActorHoldsTargetPermission_IsAllowed()
    {
        using var host = SentinelTestHost.Create();
        // Actor holds both Role.Update AND Invoice.Read — allowed.
        using var client = host.CreateClient("admin", RoleUpdate, "Permission.Invoice.Read");

        var body     = JsonContent.Create(new { permissionId = "Permission.Invoice.Read" });
        var response = await client.PostAsync($"/api/auth/roles/{Guid.NewGuid()}/permissions", body);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ── 403 — Privilege-escalation guard (AssignRole) ────────────────────────

    [Fact]
    public async Task AssignRole_ActorLacksRolePermission_Returns403()
    {
        using var host = SentinelTestHost.Create();
        var userId     = Guid.NewGuid();
        var roleId     = Guid.NewGuid();

        // The role being assigned grants a permission the actor does not hold.
        host.RoleRepo.GetByIdAsync(roleId, Arg.Any<CancellationToken>())
                     .Returns(new RoleDto(
                         roleId, "invoice-approver", "Invoice Approver", "Default",
                         RequiresDualApproval: false,
                         Permissions: [new PermissionDto("Permission.Invoice.Approve", "Invoice", "Approve", "Finance", "")]));

        // Actor only has User.Update -- not the role's own Invoice.Approve permission.
        using var client = host.CreateClient("admin", UserUpdate);
        var body         = JsonContent.Create(new { roleId });
        var response     = await client.PostAsync($"/api/auth/users/{userId}/roles", body);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden,
            "an actor cannot assign a role bundling permissions they do not themselves hold");
    }

    [Fact]
    public async Task AssignRole_ActorHoldsRolePermission_IsAllowed()
    {
        using var host = SentinelTestHost.Create();
        var userId     = Guid.NewGuid();
        var roleId     = Guid.NewGuid();
        const string perm = "Permission.Invoice.Approve";

        host.RoleRepo.GetByIdAsync(roleId, Arg.Any<CancellationToken>())
                     .Returns(new RoleDto(
                         roleId, "invoice-approver", "Invoice Approver", "Default",
                         RequiresDualApproval: false,
                         Permissions: [new PermissionDto(perm, "Invoice", "Approve", "Finance", "")]));

        // Actor holds both User.Update AND the role's own Invoice.Approve permission.
        using var client = host.CreateClient("admin", UserUpdate, perm);
        var body         = JsonContent.Create(new { roleId });
        var response     = await client.PostAsync($"/api/auth/users/{userId}/roles", body);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ── 409 — Separation-of-Duties guard ─────────────────────────────────────

    [Fact]
    public async Task AssignPermission_SodConflict_Returns409()
    {
        using var host        = SentinelTestHost.Create();
        var roleId            = Guid.NewGuid();
        const string perm     = "Permission.Invoice.Approve";

        host.ConflictRepo.HasConflictAsync(roleId, perm, Arg.Any<CancellationToken>())
                         .Returns(true);

        // Actor holds the permission they are trying to grant.
        using var client = host.CreateClient("admin", RoleUpdate, perm);
        var body         = JsonContent.Create(new { permissionId = perm });
        var response     = await client.PostAsync($"/api/auth/roles/{roleId}/permissions", body);

        response.StatusCode.Should().Be(HttpStatusCode.Conflict,
            "Separation of Duties: conflicting permission pair must be rejected");
    }

    // ── 4-Eyes / Dual-approval flow ───────────────────────────────────────────

    [Fact]
    public async Task AssignRole_DualApprovalRole_Returns202WithPendingId()
    {
        using var host = SentinelTestHost.Create();
        var userId     = Guid.NewGuid();
        var roleId     = Guid.NewGuid();

        host.RoleRepo.RequiresDualApprovalAsync(roleId, Arg.Any<CancellationToken>())
                     .Returns(true);
        host.PendingRepo.CreateAsync(userId, roleId, Arg.Any<DateTime?>(), Arg.Any<CancellationToken>())
                        .Returns(PendingAssignment.Create(userId, roleId, "admin"));

        using var client = host.CreateClient("admin", UserUpdate);
        var body         = JsonContent.Create(new { roleId });
        var response     = await client.PostAsync($"/api/auth/users/{userId}/roles", body);

        response.StatusCode.Should().Be(HttpStatusCode.Accepted,
            "a role requiring dual-approval must return 202 with pendingAssignmentId");
    }

    [Fact]
    public async Task ApproveAssignment_WhenRepositoryReturnsFalse_Returns409()
    {
        using var host = SentinelTestHost.Create();

        host.PendingRepo.ApproveAsync(Arg.Any<Guid>(), Arg.Any<CancellationToken>())
                        .Returns(false);

        using var client = host.CreateClient("approver", UserUpdate);
        var response     = await client.PostAsync(
            $"/api/auth/pending-assignments/{Guid.NewGuid()}/approve", null);

        response.StatusCode.Should().Be(HttpStatusCode.Conflict,
            "failed approval (same actor as requestor, expired, or already reviewed) returns 409");
    }
}
