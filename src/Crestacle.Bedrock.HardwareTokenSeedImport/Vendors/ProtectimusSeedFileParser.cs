namespace Crestacle.Bedrock.HardwareTokenSeedImport.Vendors;

/// <summary>
/// Parses the seed-file export Protectimus delivers after a hardware token order.
/// </summary>
/// <remarks>
/// Not yet implemented: the exact export format (CSV vs. PSKC XML, column/field names,
/// secret encoding) must be confirmed against a real Protectimus order export before
/// this can be written.
/// </remarks>
public sealed class ProtectimusSeedFileParser : ISeedFileParser
{
    public IReadOnlyList<SeedRecord> Parse(Stream seedFile)
        => throw new NotImplementedException(
            "Needs a sample Protectimus seed-file export to confirm the format before implementing.");
}
