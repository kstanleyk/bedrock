using Crestacle.Bedrock.HardwareTokenSeedImport.Vendors;
using FluentAssertions;
using Xunit;

namespace Crestacle.Bedrock.Tests.Unit.HardwareTokenSeedImport;

public class ProtectimusSeedFileParserTests
{
    [Fact]
    public void Parse_ThrowsUntilRealExportFormatIsConfirmed()
    {
        var parser = new ProtectimusSeedFileParser();
        using var stream = new MemoryStream();

        var act = () => parser.Parse(stream);

        act.Should().Throw<NotImplementedException>();
    }
}
