using Crestacle.Bedrock.Core.Entities;
using Crestacle.Bedrock.Core.Enumerations;
using Crestacle.Bedrock.Tests.Integration.Infrastructure;
using Crestacle.Bedrock.Tests.Integration.Infrastructure.Postgres;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Crestacle.Bedrock.Tests.Integration.Controllers.Postgres;

/// <summary>
/// G2 — PostgreSQL provider schema validation tests.
///
/// These tests explicitly assert the four concerns listed in the G2 spec:
///   1. snake_case column name mapping
///   2. DateTime UTC handling (UtcDateTimeConverter round-trip)
///   3. varchar max-length enforcement at the database level
///   4. enum-as-string storage (no integer ordinal in the column)
/// </summary>
[Collection("Postgres")]
[Trait("Provider", "Postgres")]
public sealed class PostgresSchemaTests : IDisposable
{
    private readonly TestBedrockContext _db;

    public PostgresSchemaTests() => _db = PostgresDbContextFactory.Create();

    // ─────────────────────────────────────────────────────────────────────────
    // 1. snake_case column name mapping
    // ─────────────────────────────────────────────────────────────────────────

    [PostgresFact]
    public async Task UserCredentials_Table_HasSnakeCaseColumns()
    {
        var columns = await _db.Database
            .SqlQueryRaw<string>(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE lower(table_schema) = 'auth'
                  AND table_name          = 'user_credentials'
                """)
            .ToListAsync();

        columns.Should().Contain("user_id",               because: "UserId maps to snake_case user_id");
        columns.Should().Contain("email",                  because: "Email maps to column email");
        columns.Should().Contain("password_hash",          because: "PasswordHash maps to snake_case password_hash");
        columns.Should().Contain("email_confirmed",        because: "EmailConfirmed maps to snake_case email_confirmed");
        columns.Should().Contain("failed_login_attempts",  because: "FailedLoginAttempts maps to snake_case");
        columns.Should().NotContain("UserId",              because: "PascalCase column names indicate a missing snake_case mapping");
        columns.Should().NotContain("PasswordHash",        because: "PascalCase column names indicate a missing snake_case mapping");
    }

    [PostgresFact]
    public async Task AuditLog_Table_HasSnakeCaseColumns()
    {
        var columns = await _db.Database
            .SqlQueryRaw<string>(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE lower(table_schema) = 'auth'
                  AND table_name          = 'audit_log'
                """)
            .ToListAsync();

        columns.Should().Contain("user_id",    because: "UserId maps to snake_case user_id");
        columns.Should().Contain("event_type", because: "EventType maps to snake_case event_type");
        columns.Should().Contain("ip_address", because: "IpAddress maps to snake_case ip_address");
        columns.Should().Contain("occurred_at",because: "OccurredAt maps to snake_case occurred_at");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. DateTime UTC handling
    // ─────────────────────────────────────────────────────────────────────────

    [PostgresFact]
    public async Task UserCredential_CreatedAt_RoundTripsAsUtc()
    {
        var credential = UserCredential.Create(Guid.NewGuid(), "utc-test@example.com", new string('x', 60));
        _db.UserCredentials.Add(credential);
        await _db.SaveChangesAsync();
        _db.ChangeTracker.Clear();

        var loaded = await _db.UserCredentials.FirstAsync(c => c.Email == "utc-test@example.com");

        loaded.CreatedAt.Kind.Should().Be(DateTimeKind.Utc,
            because: "UtcDateTimeConverter must ensure all DateTime values are read back with Kind=Utc");
        loaded.UpdatedAt.Kind.Should().Be(DateTimeKind.Utc,
            because: "UtcDateTimeConverter must apply to UpdatedAt as well");
    }

    [PostgresFact]
    public async Task AuditEntry_OccurredAt_RoundTripsAsUtc()
    {
        var entry = AuditEntry.Create(
            AuditEventType.LoginSucceeded, "127.0.0.1", "test-agent", Guid.NewGuid());
        _db.AuditEntries.Add(entry);
        await _db.SaveChangesAsync();
        _db.ChangeTracker.Clear();

        var loaded = await _db.AuditEntries.FirstAsync(a => a.Id == entry.Id);

        loaded.OccurredAt.Kind.Should().Be(DateTimeKind.Utc,
            because: "OccurredAt must be stored and retrieved as UTC");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 3. varchar max-length enforcement
    // ─────────────────────────────────────────────────────────────────────────

    [PostgresFact]
    public async Task UserCredential_Email_ExceedingMaxLength_ThrowsAtDatabase()
    {
        // email is varchar(256); 257 chars must be rejected by PostgreSQL itself
        var oversizedEmail = new string('a', 251) + "@x.com"; // 257 chars
        var credential = UserCredential.Create(Guid.NewGuid(), oversizedEmail, new string('x', 60));
        _db.UserCredentials.Add(credential);

        var act = () => _db.SaveChangesAsync();

        await act.Should().ThrowAsync<DbUpdateException>(
            because: "PostgreSQL varchar(256) must reject email values longer than 256 characters");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 4. enum-as-string storage
    // ─────────────────────────────────────────────────────────────────────────

    [PostgresFact]
    public async Task AuditEntry_EventType_IsStoredAsStringNotInteger()
    {
        var entry = AuditEntry.Create(
            AuditEventType.LoginSucceeded, "127.0.0.1", "test-agent", Guid.NewGuid());
        _db.AuditEntries.Add(entry);
        await _db.SaveChangesAsync();

        // SqlQuery<string> expects EF Core's primitive-scalar convention: column alias "Value".
        var raw = await _db.Database
            .SqlQuery<string>($"SELECT event_type::text AS \"Value\" FROM auth.audit_log WHERE id = {entry.Id}")
            .FirstAsync();

        raw.Should().Be("LoginSucceeded",
            because: "HasConversion<string>() must store the enum name, not its integer ordinal");
        int.TryParse(raw, out _).Should().BeFalse(
            because: "an integer in event_type would indicate enum-as-int storage");
    }

    [PostgresFact]
    public async Task UserCredential_Status_IsStoredAsStringNotInteger()
    {
        var credential = UserCredential.Create(Guid.NewGuid(), "enum-test@example.com", new string('x', 60));
        _db.UserCredentials.Add(credential);
        await _db.SaveChangesAsync();

        var raw = await _db.Database
            .SqlQuery<string>($"SELECT status::text AS \"Value\" FROM auth.user_credentials WHERE id = {credential.Id}")
            .FirstAsync();

        raw.Should().Be("PendingVerification",
            because: "AccountStatus must be stored as its string name via HasConversion<string>()");
        int.TryParse(raw, out _).Should().BeFalse(
            because: "an integer in status would indicate enum-as-int storage");
    }

    public void Dispose() => _db.Dispose();
}
