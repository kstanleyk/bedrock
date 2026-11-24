using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Crestacle.Bedrock.Core.Options;
using FluentAssertions;
using Xunit;

namespace Crestacle.Bedrock.Tests.Unit.Services;

public sealed class BedrockOptionsTests
{
    [Fact]
    public void Validate_ShortSigningKey_Throws()
    {
        var opts = new BedrockOptions();
        opts.Jwt.SigningKey = "too-short-key"; // < 32 characters

        var act = () => opts.Validate();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*32*");
    }

    [Fact]
    public void Validate_SigningKeyAtLeast32Characters_DoesNotThrow()
    {
        var opts = new BedrockOptions();
        opts.Jwt.SigningKey = "Bedrock-Unit-Test-Signing-Key-32B!"; // 34 chars

        var act = () => opts.Validate();

        act.Should().NotThrow();
    }

    [Fact]
    public void Validate_CertificateOnlyConfig_NoSigningKeySet_DoesNotThrow()
    {
        var opts = new BedrockOptions();
        opts.Jwt.SigningKey = null;
        opts.Jwt.SigningCertificate = CreateEphemeralCertificate();

        try
        {
            var act = () => opts.Validate();

            act.Should().NotThrow();
        }
        finally
        {
            opts.Jwt.SigningCertificate?.Dispose();
        }
    }

    private static X509Certificate2 CreateEphemeralCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=Bedrock-Unit-Test-RS256",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        using var temp = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddHours(1));

#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12(temp.Export(X509ContentType.Pfx), password: null);
#else
        return new X509Certificate2(temp.Export(X509ContentType.Pfx));
#endif
    }
}
