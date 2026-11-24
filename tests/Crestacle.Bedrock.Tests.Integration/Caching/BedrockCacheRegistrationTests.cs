using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.EntityFramework;
using Crestacle.Bedrock.EntityFramework.Extensions;
using Crestacle.Bedrock.Tests.Integration.Infrastructure;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Crestacle.Bedrock.Tests.Integration.Caching;

/// <summary>
/// Regression coverage for the AddBedrockEntityFramework DI registration itself (not the
/// MemoryBedrockCache class, covered separately in MemoryBedrockCacheTests.cs). The bug this
/// guards against lived entirely in the registration lifetime: AddScoped gave every request a
/// fresh MemoryBedrockCache instance with its own private _lockGate field, so the lock statement
/// in TryAcquireLockAsync never actually serialized two concurrent requests against each other --
/// silently defeating the documented single-node NX-gate guarantee even within one process.
/// </summary>
public sealed class BedrockCacheRegistrationTests : IDisposable
{
    private readonly TestBedrockContext _context;
    private readonly Microsoft.Data.Sqlite.SqliteConnection _connection;
    private readonly ServiceProvider _provider;

    public BedrockCacheRegistrationTests()
    {
        (_context, _connection) = DbContextFactory.Create();

        var services = new ServiceCollection();
        services.AddSingleton<BedrockContext>(_context);
        services.AddBedrockEntityFramework<BedrockContext>();
        _provider = services.BuildServiceProvider();
    }

    [Fact]
    public void IBedrockCache_IsRegisteredAsSingleton_SameInstanceAcrossScopes()
    {
        using var scopeA = _provider.CreateScope();
        using var scopeB = _provider.CreateScope();

        var cacheA = scopeA.ServiceProvider.GetRequiredService<IBedrockCache>();
        var cacheB = scopeB.ServiceProvider.GetRequiredService<IBedrockCache>();

        cacheA.Should().BeSameAs(cacheB,
            "TryAcquireLockAsync's correctness depends on every caller sharing the same " +
            "MemoryBedrockCache instance (and therefore the same _lockGate) -- an AddScoped " +
            "registration would resolve a DIFFERENT instance per scope here and fail this assertion");
    }

    [Fact]
    public async Task TryAcquireLockAsync_ResolvedFromDifferentScopes_SerializesCorrectly()
    {
        // Simulates two concurrent HTTP requests (each gets its own DI scope) racing to acquire
        // the same lock key -- the exact scenario AddScoped broke.
        using var scopeA = _provider.CreateScope();
        using var scopeB = _provider.CreateScope();

        var cacheA = scopeA.ServiceProvider.GetRequiredService<IBedrockCache>();
        var cacheB = scopeB.ServiceProvider.GetRequiredService<IBedrockCache>();

        var results = await Task.WhenAll(
            Task.Run(() => cacheA.TryAcquireLockAsync("cross-scope-race", TimeSpan.FromSeconds(5))),
            Task.Run(() => cacheB.TryAcquireLockAsync("cross-scope-race", TimeSpan.FromSeconds(5))));

        results.Count(r => r).Should().Be(1,
            "exactly one of two concurrent, different-scope callers must win the lock");
    }

    public void Dispose()
    {
        _provider.Dispose();
        _context.Dispose();
        _connection.Dispose();
    }
}
