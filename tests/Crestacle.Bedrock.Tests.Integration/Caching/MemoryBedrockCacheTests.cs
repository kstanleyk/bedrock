using Crestacle.Bedrock.EntityFramework.Caching;
using FluentAssertions;
using Microsoft.Extensions.Caching.Memory;
using Xunit;

namespace Crestacle.Bedrock.Tests.Integration.Caching;

public sealed class MemoryBedrockCacheTests : IDisposable
{
    private readonly IMemoryCache _memoryCache = new MemoryCache(new MemoryCacheOptions());
    private readonly MemoryBedrockCache _cache;

    public MemoryBedrockCacheTests()
    {
        _cache = new MemoryBedrockCache(_memoryCache);
    }

    [Fact]
    public async Task SetAsync_ThenGetAsync_ReturnsStoredValue()
    {
        await _cache.SetAsync("key1", "value1", TimeSpan.FromMinutes(5));

        var result = await _cache.GetAsync("key1");

        result.Should().Be("value1");
    }

    [Fact]
    public async Task GetAsync_UnknownKey_ReturnsNull()
    {
        var result = await _cache.GetAsync("no-such-key");

        result.Should().BeNull();
    }

    [Fact]
    public async Task ExistsAsync_AfterSet_ReturnsTrue()
    {
        await _cache.SetAsync("exists-key", "v", TimeSpan.FromMinutes(1));

        var exists = await _cache.ExistsAsync("exists-key");

        exists.Should().BeTrue();
    }

    [Fact]
    public async Task ExistsAsync_UnknownKey_ReturnsFalse()
    {
        var exists = await _cache.ExistsAsync("ghost");

        exists.Should().BeFalse();
    }

    [Fact]
    public async Task RemoveAsync_ExistingKey_KeyNoLongerExists()
    {
        await _cache.SetAsync("remove-me", "val", TimeSpan.FromMinutes(1));

        await _cache.RemoveAsync("remove-me");

        var exists = await _cache.ExistsAsync("remove-me");
        exists.Should().BeFalse();
    }

    [Fact]
    public async Task SetAsync_Expired_ReturnsNull()
    {
        await _cache.SetAsync("expiring", "v", TimeSpan.FromMilliseconds(1));
        await Task.Delay(50);

        var result = await _cache.GetAsync("expiring");

        result.Should().BeNull();
    }

    // -------------------------------------------------------------------------
    // TryAcquireLockAsync / ReleaseLockAsync
    // -------------------------------------------------------------------------

    [Fact]
    public async Task TryAcquireLockAsync_KeyNotHeld_AcquiresAndReturnsTrue()
    {
        var acquired = await _cache.TryAcquireLockAsync("lock-key", TimeSpan.FromSeconds(5));

        acquired.Should().BeTrue();
    }

    [Fact]
    public async Task TryAcquireLockAsync_AlreadyHeld_ReturnsFalse()
    {
        await _cache.TryAcquireLockAsync("lock-key", TimeSpan.FromSeconds(5));

        var secondAttempt = await _cache.TryAcquireLockAsync("lock-key", TimeSpan.FromSeconds(5));

        secondAttempt.Should().BeFalse();
    }

    [Fact]
    public async Task ReleaseLockAsync_ThenTryAcquire_SucceedsAgain()
    {
        await _cache.TryAcquireLockAsync("lock-key", TimeSpan.FromSeconds(5));
        await _cache.ReleaseLockAsync("lock-key");

        var reacquired = await _cache.TryAcquireLockAsync("lock-key", TimeSpan.FromSeconds(5));

        reacquired.Should().BeTrue();
    }

    [Fact]
    public async Task TryAcquireLockAsync_ConcurrentCallersSharingTheUnderlyingCache_ExactlyOneWins()
    {
        // Simulates what AddSingleton (correct) vs AddScoped (the bug fixed in
        // BedrockEntityFrameworkServiceCollectionExtensions) actually differ on: two
        // MemoryBedrockCache INSTANCES sharing the same underlying IMemoryCache (as every
        // instance always does, singleton or not), racing for the same lock key. The NX-gate
        // guarantee (_cache.TryGetValue + _cache.Set) is atomic because both calls go through
        // the shared IMemoryCache, independent of which MemoryBedrockCache instance calls it --
        // this proves the underlying store-level atomicity; the DI lifetime bug this regression
        // guards is a SEPARATE concern, covered by BedrockCacheRegistrationTests.
        var second = new MemoryBedrockCache(_memoryCache);

        var results = await Task.WhenAll(
            Task.Run(() => _cache.TryAcquireLockAsync("race-key", TimeSpan.FromSeconds(5))),
            Task.Run(() => second.TryAcquireLockAsync("race-key", TimeSpan.FromSeconds(5))));

        results.Count(r => r).Should().Be(1, "exactly one of two concurrent racers must win an NX-style lock");
    }

    public void Dispose() => _memoryCache.Dispose();
}
