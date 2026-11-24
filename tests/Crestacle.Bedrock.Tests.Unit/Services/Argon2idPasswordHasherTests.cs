using System.Security.Cryptography;
using System.Text;
using Crestacle.Bedrock.AspNetCore.Services;
using FluentAssertions;
using Konscious.Security.Cryptography;
using Xunit;

namespace Crestacle.Bedrock.Tests.Unit.Services;

public sealed class Argon2idPasswordHasherTests
{
    private readonly Argon2idPasswordHasher _hasher = new();

    // Mirrors the real (current) production constants in Argon2idPasswordHasher, so a fake
    // "legacy, no encoded params" hash built here is honestly equivalent to one this type
    // itself would have produced before cost-parameter encoding was added.
    private const int CurrentMemorySize = 65536;
    private const int CurrentIterations = 3;
    private const int CurrentParallelism = 4;

    private static string BuildHashWithParams(string password, byte[] salt, int memorySize, int iterations, int parallelism)
    {
        var hashBytes = ComputeRaw(password, salt, memorySize, iterations, parallelism);
        return $"argon2id$m={memorySize},t={iterations},p={parallelism}" +
               $"${Convert.ToBase64String(salt)}${Convert.ToBase64String(hashBytes)}";
    }

    private static string BuildLegacyHashNoParams(string password, byte[] salt)
    {
        var hashBytes = ComputeRaw(password, salt, CurrentMemorySize, CurrentIterations, CurrentParallelism);
        return $"argon2id${Convert.ToBase64String(salt)}${Convert.ToBase64String(hashBytes)}";
    }

    private static byte[] ComputeRaw(string password, byte[] salt, int memorySize, int iterations, int parallelism)
    {
        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            MemorySize = memorySize,
            Iterations = iterations,
            DegreeOfParallelism = parallelism
        };
        return argon2.GetBytes(32);
    }

    [Fact]
    public void Hash_ProducesArgon2idPrefixedString()
    {
        var hash = _hasher.Hash("Password1!");
        hash.Should().StartWith("argon2id$");
    }

    [Fact]
    public void Hash_TwoCallsSamePasword_ProduceDifferentHashes()
    {
        var h1 = _hasher.Hash("Password1!");
        var h2 = _hasher.Hash("Password1!");
        h1.Should().NotBe(h2);
    }

    [Fact]
    public void Verify_CorrectPassword_ReturnsTrue()
    {
        var hash = _hasher.Hash("Password1!");
        _hasher.Verify("Password1!", hash).Should().BeTrue();
    }

    [Fact]
    public void Verify_WrongPassword_ReturnsFalse()
    {
        var hash = _hasher.Hash("Password1!");
        _hasher.Verify("WrongPassword1!", hash).Should().BeFalse();
    }

    [Fact]
    public void NeedsRehash_Argon2idHash_ReturnsFalse()
    {
        var hash = _hasher.Hash("Password1!");
        _hasher.NeedsRehash(hash).Should().BeFalse();
    }

    [Fact]
    public void NeedsRehash_Pbkdf2Hash_ReturnsTrue()
    {
        // ASP.NET Core Identity v3 PBKDF2-SHA256 hash of "Password1!"
        const string pbkdf2Hash = "AQAAAAIAAYagAAAAENBKnvCHHF9hJHlVv0Y+hRQOWAFP0kYV2GHHfT/B9kFE9bM7hLdNZvAVH3KD5u8P";
        _hasher.NeedsRehash(pbkdf2Hash).Should().BeTrue();
    }

    [Fact]
    public void Verify_UnknownHashFormat_ReturnsFalse()
    {
        _hasher.Verify("Password1!", "not-a-valid-hash-format").Should().BeFalse();
    }

    // -------------------------------------------------------------------------
    // Cost-parameter encoding — raising MemorySize/Iterations/Parallelism later must not
    // break verification of hashes created under the OLD parameters.
    // -------------------------------------------------------------------------

    [Fact]
    public void Hash_EncodesCurrentCostParametersInTheOutput()
    {
        var hash = _hasher.Hash("Password1!");

        hash.Should().MatchRegex(@"^argon2id\$m=\d+,t=\d+,p=\d+\$[^$]+\$[^$]+$",
            "the cost parameters actually used must be embedded in the hash itself, not " +
            "implied by whatever the current constants happen to be at verify time");
    }

    [Fact]
    public void Verify_HashWithDifferentEncodedParamsThanCurrentConstants_StillVerifiesCorrectly()
    {
        // Simulates the exact scenario this fix exists for: a hash created under OLD, weaker
        // parameters (e.g. before a security hardening raised MemorySize/Iterations) must
        // still verify correctly using ITS OWN encoded parameters, not whatever the current
        // constants are now.
        var salt = RandomNumberGenerator.GetBytes(16);
        var oldHash = BuildHashWithParams("Password1!", salt, memorySize: 1024, iterations: 1, parallelism: 1);

        _hasher.Verify("Password1!", oldHash).Should().BeTrue();
        _hasher.Verify("WrongPassword1!", oldHash).Should().BeFalse();
    }

    [Fact]
    public void NeedsRehash_HashWithOutdatedEncodedParams_ReturnsTrue()
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var oldHash = BuildHashWithParams("Password1!", salt, memorySize: 1024, iterations: 1, parallelism: 1);

        _hasher.NeedsRehash(oldHash).Should().BeTrue(
            "a hash whose encoded cost parameters no longer match the current constants must " +
            "be flagged for rehashing on next successful login");
    }

    [Fact]
    public void Verify_LegacyHashWithNoEncodedParams_StillVerifiesCorrectly()
    {
        // This type's OWN pre-fix format: argon2id${salt}${hash}, no params segment at all.
        // Must still verify correctly against the CURRENT constants, since any hash in this
        // shape was necessarily created with whatever constants were current when it was made
        // (there was no other possibility before this fix).
        var salt = RandomNumberGenerator.GetBytes(16);
        var legacyHash = BuildLegacyHashNoParams("Password1!", salt);

        _hasher.Verify("Password1!", legacyHash).Should().BeTrue();
    }

    [Fact]
    public void NeedsRehash_LegacyHashWithNoEncodedParams_ReturnsTrue()
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var legacyHash = BuildLegacyHashNoParams("Password1!", salt);

        _hasher.NeedsRehash(legacyHash).Should().BeTrue(
            "a pre-fix hash with no encoded params at all should migrate to the new, " +
            "parameter-encoded format on next successful login");
    }
}
