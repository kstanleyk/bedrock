namespace Crestacle.Bedrock.HardwareTokenSeedImport;

/// <summary>Parses one manufacturer's seed-file export into normalized <see cref="SeedRecord"/>s.</summary>
public interface ISeedFileParser
{
    IReadOnlyList<SeedRecord> Parse(Stream seedFile);
}
