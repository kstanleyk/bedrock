using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Crestacle.Bedrock.AspNetCore.Helpers;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.Core.Options;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Crestacle.Bedrock.AspNetCore.Services;

public sealed class JwtService : ITokenService
{
    private readonly JwtOptions _jwt;
    private readonly JwtSecurityTokenHandler _handler = new() { MapInboundClaims = false };

    public JwtService(IOptions<BedrockOptions> options)
    {
        _jwt = options.Value.Jwt;
    }

    // -------------------------------------------------------------------------
    // ITokenService — generation
    // -------------------------------------------------------------------------

    public string GenerateAccessToken(
        Guid userId,
        string email,
        IEnumerable<string> roles,
        string? tenantId = null,
        IDictionary<string, string>? extraClaims = null)
    {
        using var activity = BedrockTelemetry.ActivitySource.StartActivity("bedrock.token.generate");
        activity?.SetTag("bedrock.user_id", userId.ToString());
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId.ToString()),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new("user_id", userId.ToString()),
            new("email", email),
            new("token_type", "access"),
        };

        // "roles" (plural, guaranteed JSON array), NOT ClaimTypes.Role -- found while
        // building 1-BE-09-f (crestacle-core), verified against a real issued token:
        // ClaimTypes.Role's default OutboundClaimTypeMap serializes to the SHORT claim key
        // "role" (singular), and JwtPayload collapses same-keyed Claims to a bare JSON
        // STRING when there is exactly one, an array only with two or more -- neither shape
        // matches crestacle-web's own already-built AccessTokenClaims contract
        // (packages/auth/src/jwt.ts: `roles: string[]`, always an array, checked via
        // `Array.isArray`), which would throw MalformedAccessTokenError on every real login
        // regardless of role count. JsonClaimValueTypes.JsonArray forces a genuine JSON
        // array under the literal "roles" key even for a single role.
        var rolesArray = roles as string[] ?? roles.ToArray();
        claims.Add(new Claim("roles", JsonSerializer.Serialize(rolesArray), JsonClaimValueTypes.JsonArray));

        if (tenantId is not null)
            claims.Add(new Claim("tenant_id", tenantId));

        if (extraClaims is not null)
            foreach (var (key, value) in extraClaims)
                claims.Add(new Claim(key, value));

        return Issue(claims, _jwt.AccessTokenExpiry);
    }

    public string GenerateRefreshToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(64);
        return Convert.ToBase64String(bytes);
    }

    public string HashToken(string rawToken)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public string GenerateChallengeToken(Guid challengeId, Guid userId)
        => Issue(BuildShortLivedClaims(userId, challengeId, "challenge"), TimeSpan.FromMinutes(5));

    public string GenerateStepUpToken(Guid challengeId, Guid userId)
        => Issue(BuildShortLivedClaims(userId, challengeId, "step_up"), TimeSpan.FromMinutes(5));

    public string GenerateEnrollmentToken(Guid userId)
        => Issue(
            new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("user_id", userId.ToString()),
                new Claim("token_type", "enrollment"),
            },
            TimeSpan.FromMinutes(15));

    // -------------------------------------------------------------------------
    // ITokenService — validation
    // -------------------------------------------------------------------------

    public Guid? ValidateChallengeToken(string token)
        => TryExtractChallengeId(token, "challenge");

    public Guid? ValidateStepUpToken(string token)
        => TryExtractChallengeId(token, "step_up");

    public string ExtractJti(string jwtToken)
        => _handler.ReadJwtToken(jwtToken).Id;

    public (bool isValid, Guid? challengeId) ValidateAndExtractStepUp(string token, Guid expectedUserId)
    {
        try
        {
            var principal = _handler.ValidateToken(token, BuildInternalValidationParameters(), out _);

            if (principal.FindFirstValue("token_type") != "step_up")
                return (false, null);

            if (!Guid.TryParse(principal.FindFirstValue("user_id"), out var userId) || userId != expectedUserId)
                return (false, null);

            var idStr = principal.FindFirstValue("challenge_id");
            return Guid.TryParse(idStr, out var challengeId)
                ? (true, (Guid?)challengeId)
                : (false, null);
        }
        catch
        {
            return (false, null);
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private string Issue(IEnumerable<Claim> claims, TimeSpan expiry)
    {
        var now = DateTime.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Issuer = string.IsNullOrEmpty(_jwt.Issuer) ? null : _jwt.Issuer,
            Audience = string.IsNullOrEmpty(_jwt.Audience) ? null : _jwt.Audience,
            IssuedAt = now,
            Expires = now.Add(expiry),
            SigningCredentials = BedrockJwtHelper.BuildSigningCredentials(_jwt),
        };
        return _handler.WriteToken(_handler.CreateToken(descriptor));
    }

    private Guid? TryExtractChallengeId(string token, string expectedType)
    {
        try
        {
            var principal = _handler.ValidateToken(token, BuildInternalValidationParameters(), out _);
            if (principal.FindFirstValue("token_type") != expectedType) return null;
            var idStr = principal.FindFirstValue("challenge_id");
            return Guid.TryParse(idStr, out var id) ? id : null;
        }
        catch { return null; }
    }

    // Short-lived internal tokens (challenge, step_up, enrollment) don't need audience
    // validation — they're single-use, signature-protected, and validated by token_type.
    private TokenValidationParameters BuildInternalValidationParameters()
    {
        var p = BedrockJwtHelper.BuildValidationParameters(_jwt);
        p.ValidateAudience = false;
        return p;
    }

    private static IEnumerable<Claim> BuildShortLivedClaims(Guid userId, Guid challengeId, string tokenType)
        => new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim("user_id", userId.ToString()),
            new Claim("challenge_id", challengeId.ToString()),
            new Claim("token_type", tokenType),
        };
}
