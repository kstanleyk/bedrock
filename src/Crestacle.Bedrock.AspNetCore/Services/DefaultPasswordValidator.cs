using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.Core.Options;
using Microsoft.Extensions.Options;

namespace Crestacle.Bedrock.AspNetCore.Services;

/// <summary>Enforces <see cref="PasswordOptions"/> complexity rules and history-based reuse prevention.</summary>
public sealed class DefaultPasswordValidator : IPasswordValidator
{
    private readonly PasswordOptions _opts;
    private readonly IPasswordHasher _hasher;
    private readonly CommonPasswordValidator _commonValidator;

    public DefaultPasswordValidator(
        IOptions<BedrockOptions> options,
        IPasswordHasher hasher,
        CommonPasswordValidator commonValidator)
    {
        _opts = options.Value.Password;
        _hasher = hasher;
        _commonValidator = commonValidator;
    }

    public async Task<(bool IsValid, IReadOnlyList<string> Errors)> IsValidAsync(string password, CancellationToken ct = default)
    {
        var list = new List<string>();

        if (password.Length < _opts.MinLength)
            list.Add($"Password must be at least {_opts.MinLength} characters.");
        if (_opts.RequireUppercase && !password.Any(char.IsUpper))
            list.Add("Password must contain at least one uppercase letter.");
        if (_opts.RequireLowercase && !password.Any(char.IsLower))
            list.Add("Password must contain at least one lowercase letter.");
        if (_opts.RequireDigit && !password.Any(char.IsDigit))
            list.Add("Password must contain at least one digit.");
        if (_opts.RequireSpecialCharacter && !password.Any(c => !char.IsLetterOrDigit(c)))
            list.Add("Password must contain at least one special character.");

        var (commonValid, commonErrors) = await _commonValidator.IsValidAsync(password, ct).ConfigureAwait(false);
        if (!commonValid)
            list.AddRange(commonErrors);

        return (list.Count == 0, list);
    }

    public Task<bool> IsPreviouslyUsedAsync(string password, IEnumerable<string> hashes, CancellationToken ct = default)
    {
        foreach (var hash in hashes)
            if (_hasher.Verify(password, hash))
                return Task.FromResult(true);
        return Task.FromResult(false);
    }
}
