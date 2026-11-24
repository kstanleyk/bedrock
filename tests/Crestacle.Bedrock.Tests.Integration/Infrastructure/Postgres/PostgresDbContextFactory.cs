using Microsoft.EntityFrameworkCore;

namespace Crestacle.Bedrock.Tests.Integration.Infrastructure.Postgres;

internal static class PostgresDbContextFactory
{
    internal const string EnvVar = "BEDROCK_TEST_PG_CONNECTION";

    /// <summary>
    /// Creates a <see cref="TestBedrockContext"/> backed by the PostgreSQL database
    /// specified in <c>BEDROCK_TEST_PG_CONNECTION</c>. The database schema is dropped
    /// and recreated to guarantee a clean baseline for each test run.
    /// </summary>
    /// <remarks>
    /// The connection string should point to a <em>dedicated test database</em> and the
    /// connecting Postgres user must have the <c>CREATEDB</c> privilege (needed for
    /// <c>EnsureDeleted</c>). Example:
    /// <c>Host=localhost;Database=bedrock_test;Username=bedrock_ci;Password=secret</c>
    /// </remarks>
    internal static TestBedrockContext Create()
    {
        var connectionString = Environment.GetEnvironmentVariable(EnvVar)
            ?? throw new InvalidOperationException(
                $"Environment variable '{EnvVar}' is not set.");

        var options = new DbContextOptionsBuilder<TestBedrockContext>()
            .UseNpgsql(connectionString)
            .Options;

        var context = new TestBedrockContext(options);
        context.Database.EnsureDeleted();
        context.Database.EnsureCreated();
        return context;
    }

    /// <summary>
    /// Creates a second <see cref="TestBedrockContext"/> against the SAME already-created
    /// schema, without dropping/recreating it -- for tests that need two independent contexts
    /// open against the same live data (e.g. simulating two concurrent requests), where calling
    /// <see cref="Create"/> again would wipe out whatever the first context just wrote.
    /// </summary>
    internal static TestBedrockContext CreateWithoutResettingSchema()
    {
        var connectionString = Environment.GetEnvironmentVariable(EnvVar)
            ?? throw new InvalidOperationException(
                $"Environment variable '{EnvVar}' is not set.");

        var options = new DbContextOptionsBuilder<TestBedrockContext>()
            .UseNpgsql(connectionString)
            .Options;

        return new TestBedrockContext(options);
    }
}
