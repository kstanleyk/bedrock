using System.Security.Cryptography;
using System.Text;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Konscious.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace Crestacle.Bedrock.AspNetCore.Services;

/// <summary>
/// Argon2id password hasher. Hash format:
/// <c>argon2id$m={memorySize},t={iterations},p={parallelism}${base64(salt)}${base64(hash)}</c>.
/// The cost parameters are encoded in the hash itself (not just read off the current
/// <see cref="MemorySize"/>/<see cref="Iterations"/>/<see cref="Parallelism"/> constants) so
/// that raising them later -- the normal response to hardware getting faster -- re-verifies
/// every existing hash correctly against the parameters it was ACTUALLY created with, instead
/// of silently failing every login the moment the constants change. A legacy hash with no
/// encoded parameters (<c>argon2id${salt}${hash}</c>, this type's own format before this fix)
/// is still verified correctly, against the current constants -- correct, since any hash in
/// that shape was necessarily created with whatever constants were current when it was made.
/// Transparently detects and verifies legacy ASP.NET Core Identity PBKDF2 hashes
/// (v2 and v3) and BCrypt hashes (<c>$2*</c>) so they can be migrated to Argon2id
/// on next successful login.
/// </summary>
public sealed class Argon2idPasswordHasher : IPasswordHasher
{
    private const int MemorySize = 65536; // 64 MB
    private const int Iterations = 3;
    private const int Parallelism = 4;
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private const string Prefix = "argon2id$";
    private const string BcryptPrefix = "$2";

    public string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Compute(Encoding.UTF8.GetBytes(password), salt, MemorySize, Iterations, Parallelism);
        return $"{Prefix}m={MemorySize},t={Iterations},p={Parallelism}" +
               $"${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public bool Verify(string password, string hash)
    {
        if (hash.StartsWith(Prefix, StringComparison.Ordinal))
            return VerifyArgon2id(password, hash);

        if (hash.StartsWith(BcryptPrefix, StringComparison.Ordinal))
        {
            try { return BCrypt.Net.BCrypt.Verify(password, hash); }
            catch { return false; }
        }

        try
        {
            var result = new PasswordHasher<object>().VerifyHashedPassword(null!, hash, password);
            return result != PasswordVerificationResult.Failed;
        }
        catch
        {
            return false;
        }
    }

    public bool NeedsRehash(string hash)
    {
        if (!hash.StartsWith(Prefix, StringComparison.Ordinal))
            return true;

        // No encoded params segment (this type's pre-fix format) -- migrate to the new,
        // parameter-encoded format on next login even though the current constants still
        // match what it was actually hashed with.
        if (!TryParseParams(hash[Prefix.Length..], out var parsedParams, out _))
            return true;

        return parsedParams.MemorySize != MemorySize
            || parsedParams.Iterations != Iterations
            || parsedParams.Parallelism != Parallelism;
    }

    private bool VerifyArgon2id(string password, string hash)
    {
        var body = hash[Prefix.Length..];

        int memorySize = MemorySize, iterations = Iterations, parallelism = Parallelism;
        if (TryParseParams(body, out var parsedParams, out var remainder))
        {
            memorySize = parsedParams.MemorySize;
            iterations = parsedParams.Iterations;
            parallelism = parsedParams.Parallelism;
            body = remainder;
        }

        var sep = body.IndexOf('$');
        if (sep < 0) return false;

        byte[] salt, expected;
        try
        {
            salt = Convert.FromBase64String(body[..sep]);
            expected = Convert.FromBase64String(body[(sep + 1)..]);
        }
        catch { return false; }

        var actual = Compute(Encoding.UTF8.GetBytes(password), salt, memorySize, iterations, parallelism);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    /// <summary>
    /// Parses a leading <c>m={int},t={int},p={int}$</c> params segment off <paramref name="body"/>
    /// (the hash with the <see cref="Prefix"/> already stripped). Returns <see langword="false"/>
    /// (with <paramref name="remainder"/> set to <paramref name="body"/> unchanged) for a
    /// legacy hash with no params segment -- i.e. <paramref name="body"/> starts directly with
    /// base64 salt data rather than <c>m=</c>.
    /// </summary>
    private static bool TryParseParams(
        string body, out (int MemorySize, int Iterations, int Parallelism) parsedParams, out string remainder)
    {
        parsedParams = default;
        remainder = body;

        if (!body.StartsWith("m=", StringComparison.Ordinal)) return false;

        var sep = body.IndexOf('$');
        if (sep < 0) return false;

        var segment = body[..sep];
        var parts = segment.Split(',');
        if (parts.Length != 3) return false;

        try
        {
            var m = int.Parse(parts[0]["m=".Length..]);
            var t = int.Parse(parts[1]["t=".Length..]);
            var p = int.Parse(parts[2]["p=".Length..]);
            parsedParams = (m, t, p);
            remainder = body[(sep + 1)..];
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static byte[] Compute(byte[] passwordBytes, byte[] salt, int memorySize, int iterations, int parallelism)
    {
        using var argon2 = new Argon2id(passwordBytes)
        {
            Salt = salt,
            MemorySize = memorySize,
            Iterations = iterations,
            DegreeOfParallelism = parallelism
        };
        return argon2.GetBytes(HashSize);
    }
}
