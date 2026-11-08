namespace Crestacle.Bedrock.HardwareTokenSeedImport;

/// <summary>
/// One hardware token's provisioning data, normalized from whatever file format the
/// manufacturer shipped it in. <see cref="SecretBase32"/> uses the same encoding
/// <c>Crestacle.Bedrock</c> already uses for authenticator-app TOTP secrets.
/// </summary>
public sealed record SeedRecord(
    string SerialNumber,
    string SecretBase32,
    OathCredentialType Type,
    OathAlgorithm Algorithm,
    int Digits,
    TimeSpan Period,
    long? InitialCounter = null);
