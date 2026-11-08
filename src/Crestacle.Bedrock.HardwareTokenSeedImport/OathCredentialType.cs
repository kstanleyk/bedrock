namespace Crestacle.Bedrock.HardwareTokenSeedImport;

/// <summary>Whether a seed generates codes from a clock (TOTP) or an incrementing counter (HOTP).</summary>
public enum OathCredentialType
{
    Totp,
    Hotp
}
