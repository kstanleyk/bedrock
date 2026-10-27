using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Crestacle.Bedrock.AspNetCore.Services;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Crestacle.Bedrock.Core.Options;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Crestacle.Bedrock.Tests.Unit.Services;

public sealed class JwtServiceTests
{
    // 32-byte (256-bit) test key — long enough for HS256
    private const string TestSigningKey = "Bedrock-Unit-Test-Signing-Key-32B!";

    private static ITokenService CreateService(Action<JwtOptions>? configure = null)
    {
        var opts = new BedrockOptions();
        opts.Jwt.SigningKey = TestSigningKey;
        opts.Jwt.Issuer = "test-issuer";
        opts.Jwt.Audience = "test-audience";
        configure?.Invoke(opts.Jwt);
        return new JwtService(Options.Create(opts));
    }

    // -------------------------------------------------------------------------
    // GenerateAccessToken
    // -------------------------------------------------------------------------

    [Fact]
    public void GenerateAccessToken_HS256_ReturnsSignedJwt()
    {
        var svc = CreateService();
        var token = svc.GenerateAccessToken(Guid.NewGuid(), "u@test.com", ["admin"]);

        token.Should().NotBeNullOrEmpty();
        token.Split('.').Should().HaveCount(3); // header.payload.signature
    }

    [Fact]
    public void GenerateAccessToken_ContainsExpectedClaims()
    {
        var svc = CreateService();
        var userId = Guid.NewGuid();
        var token = svc.GenerateAccessToken(userId, "u@test.com", ["admin", "user"], "tenant1");

        // MapInboundClaims = false so we see the raw JWT claim names (e.g. "roles", not ClaimTypes.Role URI)
        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        var jwt = handler.ReadJwtToken(token);

        jwt.Claims.Should().Contain(c => c.Type == "sub" && c.Value == userId.ToString());
        jwt.Claims.Should().Contain(c => c.Type == "user_id" && c.Value == userId.ToString());
        jwt.Claims.Should().Contain(c => c.Type == "email" && c.Value == "u@test.com");
        jwt.Claims.Should().Contain(c => c.Type == "token_type" && c.Value == "access");
        jwt.Claims.Should().Contain(c => c.Type == "tenant_id" && c.Value == "tenant1");
        // Corrected (1-BE-09-f, crestacle-core): roles are now emitted under the literal key
        // "roles" as a genuine JSON array (JsonClaimValueTypes.JsonArray), not ClaimTypes.Role's
        // default outbound-mapped short key "role" -- verified against a real issued token that
        // the OLD "role" key was genuinely incompatible with crestacle-web's own already-built
        // AccessTokenClaims contract (packages/auth/src/jwt.ts: `roles: string[]`, always an
        // array). JwtSecurityToken.Claims flattens a JSON-array-valued claim into one Claim per
        // element, same count as before, under the corrected key.
        jwt.Claims.Count(c => c.Type == "roles").Should().Be(2);
        jwt.Claims.Select(c => c.Value).Should().Contain(["admin", "user"]);
        jwt.Claims.Should().Contain(c => c.Type == "jti");
    }

    [Fact]
    public void GenerateAccessToken_WithExtraClaims_IncludesExtra()
    {
        var svc = CreateService();
        var extra = new Dictionary<string, string> { ["custom"] = "value" };
        var token = svc.GenerateAccessToken(Guid.NewGuid(), "u@test.com", [], extraClaims: extra);

        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);
        jwt.Claims.Should().Contain(c => c.Type == "custom" && c.Value == "value");
    }

    [Fact]
    public void GenerateAccessToken_NoTenantId_NoTenantClaim()
    {
        var svc = CreateService();
        var token = svc.GenerateAccessToken(Guid.NewGuid(), "u@test.com", []);

        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);
        jwt.Claims.Should().NotContain(c => c.Type == "tenant_id");
    }

    // -------------------------------------------------------------------------
    // GenerateRefreshToken / HashToken
    // -------------------------------------------------------------------------

    [Fact]
    public void GenerateRefreshToken_ReturnsBase64_64Bytes()
    {
        var svc = CreateService();
        var raw = svc.GenerateRefreshToken();

        var bytes = Convert.FromBase64String(raw);
        bytes.Should().HaveCount(64);
    }

    [Fact]
    public void HashToken_ReturnsSha256HexLowercase()
    {
        var svc = CreateService();
        var hash = svc.HashToken("hello");

        hash.Should().HaveLength(64);
        hash.Should().Be(hash.ToLowerInvariant());
        hash.Should().MatchRegex("^[0-9a-f]+$");
    }

    [Fact]
    public void HashToken_SameInput_SameOutput()
    {
        var svc = CreateService();
        var h1 = svc.HashToken("abc");
        var h2 = svc.HashToken("abc");
        h1.Should().Be(h2);
    }

    // -------------------------------------------------------------------------
    // GenerateChallengeToken
    // -------------------------------------------------------------------------

    [Fact]
    public void GenerateChallengeToken_ContainsExpectedClaims()
    {
        var svc = CreateService();
        var challengeId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var token = svc.GenerateChallengeToken(challengeId, userId);

        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);

        jwt.Claims.Should().Contain(c => c.Type == "token_type" && c.Value == "challenge");
        jwt.Claims.Should().Contain(c => c.Type == "challenge_id" && c.Value == challengeId.ToString());
        jwt.Claims.Should().Contain(c => c.Type == "user_id" && c.Value == userId.ToString());
        jwt.ValidTo.Should().BeCloseTo(DateTime.UtcNow.AddMinutes(5), TimeSpan.FromSeconds(30));
    }

    // -------------------------------------------------------------------------
    // GenerateStepUpToken
    // -------------------------------------------------------------------------

    [Fact]
    public void GenerateStepUpToken_ContainsStepUpType()
    {
        var svc = CreateService();
        var token = svc.GenerateStepUpToken(Guid.NewGuid(), Guid.NewGuid());

        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);
        jwt.Claims.Should().Contain(c => c.Type == "token_type" && c.Value == "step_up");
    }

    // -------------------------------------------------------------------------
    // GenerateEnrollmentToken
    // -------------------------------------------------------------------------

    [Fact]
    public void GenerateEnrollmentToken_ContainsEnrollmentTypeAndNoRoles()
    {
        var svc = CreateService();
        var token = svc.GenerateEnrollmentToken(Guid.NewGuid());

        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);
        jwt.Claims.Should().Contain(c => c.Type == "token_type" && c.Value == "enrollment");
        jwt.Claims.Should().NotContain(c => c.Type == ClaimTypes.Role);
        jwt.ValidTo.Should().BeCloseTo(DateTime.UtcNow.AddMinutes(15), TimeSpan.FromSeconds(30));
    }

    // -------------------------------------------------------------------------
    // ValidateChallengeToken
    // -------------------------------------------------------------------------

    [Fact]
    public void ValidateChallengeToken_ValidToken_ReturnsChallengeId()
    {
        var svc = CreateService();
        var challengeId = Guid.NewGuid();
        var token = svc.GenerateChallengeToken(challengeId, Guid.NewGuid());

        var result = svc.ValidateChallengeToken(token);

        result.Should().Be(challengeId);
    }

    [Fact]
    public void ValidateChallengeToken_WrongType_ReturnsNull()
    {
        var svc = CreateService();
        var stepUpToken = svc.GenerateStepUpToken(Guid.NewGuid(), Guid.NewGuid());

        var result = svc.ValidateChallengeToken(stepUpToken);

        result.Should().BeNull();
    }

    [Fact]
    public void ValidateChallengeToken_InvalidSignature_ReturnsNull()
    {
        var svc = CreateService();
        var result = svc.ValidateChallengeToken("not.a.jwt");

        result.Should().BeNull();
    }

    [Fact]
    public void ValidateChallengeToken_ExpiredToken_ReturnsNull()
    {
        var svc = CreateService();

        // Build an expired challenge token using the JwtSecurityToken constructor
        // (SecurityTokenDescriptor rejects Expires < NotBefore, so we bypass it by
        // supplying both notBefore and expires explicitly in the past)
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(TestSigningKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var expiredJwt = new JwtSecurityToken(
            issuer: "test-issuer",
            audience: "test-audience",
            claims: new[]
            {
                new Claim("token_type", "challenge"),
                new Claim("challenge_id", Guid.NewGuid().ToString()),
                new Claim("user_id", Guid.NewGuid().ToString()),
            },
            notBefore: DateTime.UtcNow.AddDays(-2),
            expires: DateTime.UtcNow.AddDays(-1),
            signingCredentials: creds);
        var expiredToken = new JwtSecurityTokenHandler().WriteToken(expiredJwt);

        var result = svc.ValidateChallengeToken(expiredToken);

        result.Should().BeNull();
    }

    // -------------------------------------------------------------------------
    // ValidateStepUpToken
    // -------------------------------------------------------------------------

    [Fact]
    public void ValidateStepUpToken_ValidToken_ReturnsChallengeId()
    {
        var svc = CreateService();
        var challengeId = Guid.NewGuid();
        var token = svc.GenerateStepUpToken(challengeId, Guid.NewGuid());

        var result = svc.ValidateStepUpToken(token);

        result.Should().Be(challengeId);
    }

    [Fact]
    public void ValidateStepUpToken_WrongType_ReturnsNull()
    {
        var svc = CreateService();
        var challengeToken = svc.GenerateChallengeToken(Guid.NewGuid(), Guid.NewGuid());

        var result = svc.ValidateStepUpToken(challengeToken);

        result.Should().BeNull();
    }

    // -------------------------------------------------------------------------
    // ValidateAndExtractStepUp
    // -------------------------------------------------------------------------

    [Fact]
    public void ValidateAndExtractStepUp_CorrectUser_ReturnsTrueWithChallengeId()
    {
        var svc = CreateService();
        var challengeId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var token = svc.GenerateStepUpToken(challengeId, userId);

        var (isValid, extracted) = svc.ValidateAndExtractStepUp(token, userId);

        isValid.Should().BeTrue();
        extracted.Should().Be(challengeId);
    }

    [Fact]
    public void ValidateAndExtractStepUp_WrongUserId_ReturnsFalse()
    {
        var svc = CreateService();
        var token = svc.GenerateStepUpToken(Guid.NewGuid(), Guid.NewGuid());

        var (isValid, extracted) = svc.ValidateAndExtractStepUp(token, Guid.NewGuid());

        isValid.Should().BeFalse();
        extracted.Should().BeNull();
    }

    [Fact]
    public void ValidateAndExtractStepUp_WrongTokenType_ReturnsFalse()
    {
        var svc = CreateService();
        var userId = Guid.NewGuid();
        var challengeToken = svc.GenerateChallengeToken(Guid.NewGuid(), userId);

        var (isValid, _) = svc.ValidateAndExtractStepUp(challengeToken, userId);

        isValid.Should().BeFalse();
    }
}
