using System.IO.Compression;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.Core.Options;
using Microsoft.Extensions.Options;

namespace Crestacle.Bedrock.AspNetCore.Services;

/// <summary>
/// Rejects passwords found in a configurable deny-list of common/weak passwords.
/// Disabled (passes all passwords) when <see cref="PasswordOptions.CommonPasswordDenyListPath"/> is null.
/// </summary>
public sealed class CommonPasswordValidator : IPasswordValidator
{
    internal const string DenyMessage =
        "This password is too common. Please choose a different password.";

    private const string EmbeddedSentinel = "embedded";
    private const string EmbeddedResourceName =
        "Crestacle.Bedrock.AspNetCore.Resources.common-passwords.txt.gz";

    private readonly HashSet<string>? _denyList;

    public CommonPasswordValidator(IOptions<BedrockOptions> options)
    {
        var path = options.Value.Password.CommonPasswordDenyListPath;
        if (path is null) return;

        _denyList = path.Equals(EmbeddedSentinel, StringComparison.OrdinalIgnoreCase)
            ? LoadEmbedded()
            : LoadFromFile(path);
    }

    /// <inheritdoc/>
    public Task<(bool IsValid, IReadOnlyList<string> Errors)> IsValidAsync(string password, CancellationToken ct = default)
    {
        if (_denyList is not null && _denyList.Contains(password))
            return Task.FromResult<(bool, IReadOnlyList<string>)>((false, [DenyMessage]));

        return Task.FromResult<(bool, IReadOnlyList<string>)>((true, []));
    }

    /// <inheritdoc/>
    public Task<bool> IsPreviouslyUsedAsync(string password, IEnumerable<string> hashes, CancellationToken ct = default)
        => Task.FromResult(false);

    private static HashSet<string> LoadEmbedded()
    {
        var assembly = typeof(CommonPasswordValidator).Assembly;
        using var stream = assembly.GetManifestResourceStream(EmbeddedResourceName)
            ?? throw new InvalidOperationException(
                $"Embedded resource '{EmbeddedResourceName}' not found in assembly '{assembly.GetName().Name}'.");
        return ReadLines(stream, compressed: true);
    }

    private static HashSet<string> LoadFromFile(string path)
    {
        using var stream = File.OpenRead(path);
        var compressed = path.EndsWith(".gz", StringComparison.OrdinalIgnoreCase);
        return ReadLines(stream, compressed);
    }

    private static HashSet<string> ReadLines(Stream stream, bool compressed)
    {
        Stream source = compressed ? new GZipStream(stream, CompressionMode.Decompress) : stream;
        try
        {
            using var reader = new StreamReader(source, leaveOpen: false);
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string? line;
            while ((line = reader.ReadLine()) is not null)
            {
                var trimmed = line.Trim();
                if (trimmed.Length > 0)
                    set.Add(trimmed);
            }
            return set;
        }
        finally
        {
            if (compressed) source.Dispose();
        }
    }
}
