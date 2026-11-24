using System.Security.Cryptography.X509Certificates;
using System.Text;
using Crestacle.Bedrock.Core.Options;
using Microsoft.IdentityModel.Tokens;

namespace Crestacle.Bedrock.AspNetCore.Helpers;

internal static class BedrockJwtHelper
{
    internal static SigningCredentials BuildSigningCredentials(JwtOptions jwt)
    {
        if (jwt.SigningCertificate is not null)
            return new SigningCredentials(new X509SecurityKey(jwt.SigningCertificate), SecurityAlgorithms.RsaSha256);

        return new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.SigningKey!)),
            SecurityAlgorithms.HmacSha256);
    }

    internal static SecurityKey BuildValidationKey(JwtOptions jwt)
    {
        if (jwt.SigningCertificate is not null)
            return new X509SecurityKey(jwt.SigningCertificate);

        return new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.SigningKey!));
    }

    internal static TokenValidationParameters BuildValidationParameters(JwtOptions jwt)
    {
        // Always start with the current (primary) key.
        var keys = new List<SecurityKey> { BuildValidationKey(jwt) };

        // Include the previous key during a rotation grace period so tokens signed
        // with the old key continue to validate until they expire naturally.
        if (!string.IsNullOrEmpty(jwt.PreviousSigningKey))
            keys.Add(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.PreviousSigningKey)));
        else if (jwt.PreviousSigningCertificate is not null)
            keys.Add(new X509SecurityKey(jwt.PreviousSigningCertificate));

        return new TokenValidationParameters
        {
            ValidateIssuer = !string.IsNullOrEmpty(jwt.Issuer),
            ValidIssuer = jwt.Issuer,
            ValidateAudience = !string.IsNullOrEmpty(jwt.Audience),
            ValidAudience = jwt.Audience,
            ValidateLifetime = true,
            ClockSkew = jwt.ClockSkew,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = keys,
            NameClaimType = "user_id",
            // JwtService.GenerateAccessToken embeds roles under the literal "roles" claim key
            // as a JSON array (see its own comment for why: ClaimTypes.Role's default outbound
            // mapping produces a shape crestacle-web's client contract doesn't expect), NOT
            // under ClaimTypes.Role -- RoleClaimType must match that or User.IsInRole()/
            // [Authorize(Roles = ...)] silently never match any role on a Bedrock-issued token.
            RoleClaimType = "roles",
        };
    }
}
