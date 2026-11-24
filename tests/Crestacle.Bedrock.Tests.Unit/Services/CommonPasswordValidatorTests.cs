using System.IO.Compression;
using Crestacle.Bedrock.AspNetCore.Services;
using Crestacle.Bedrock.Core.Options;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Crestacle.Bedrock.Tests.Unit.Services;

public sealed class CommonPasswordValidatorTests
{
    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static CommonPasswordValidator Build(string? path)
    {
        var opts = new BedrockOptions
        {
            Password = new PasswordOptions { CommonPasswordDenyListPath = path }
        };
        return new CommonPasswordValidator(Options.Create(opts));
    }

    private static string WritePlainTempFile(IEnumerable<string> passwords)
    {
        var path = Path.GetTempFileName();
        File.WriteAllLines(path, passwords);
        return path;
    }

    private static string WriteGzipTempFile(IEnumerable<string> passwords)
    {
        var path = Path.GetTempFileName() + ".gz";
        using var fileStream = File.Create(path);
        using var gzip = new GZipStream(fileStream, CompressionMode.Compress);
        using var writer = new StreamWriter(gzip);
        foreach (var line in passwords)
            writer.WriteLine(line);
        return path;
    }

    // -------------------------------------------------------------------------
    // Deny-list disabled
    // -------------------------------------------------------------------------

    [Fact]
    public async Task IsValid_PathNull_PassesEverything()
    {
        var validator = Build(null);
        var (valid, errors) = await validator.IsValidAsync("password");
        valid.Should().BeTrue();
        errors.Should().BeEmpty();
    }

    // -------------------------------------------------------------------------
    // Plain-text file
    // -------------------------------------------------------------------------

    [Fact]
    public async Task IsValid_PasswordInPlainTextFile_ReturnsFalse()
    {
        var path = WritePlainTempFile(["letmein", "monkey", "dragon"]);
        try
        {
            var validator = Build(path);
            var (result, errors) = await validator.IsValidAsync("monkey");
            result.Should().BeFalse();
            errors.Should().ContainSingle().Which.Should().Contain("too common");
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task IsValid_PasswordNotInList_ReturnsTrue()
    {
        var path = WritePlainTempFile(["letmein", "monkey"]);
        try
        {
            var validator = Build(path);
            var (valid, errors) = await validator.IsValidAsync("Wr@ppedC0met#9x!");
            valid.Should().BeTrue();
            errors.Should().BeEmpty();
        }
        finally { File.Delete(path); }
    }

    // -------------------------------------------------------------------------
    // Gzip file
    // -------------------------------------------------------------------------

    [Fact]
    public async Task IsValid_PasswordInGzipFile_ReturnsFalse()
    {
        var path = WriteGzipTempFile(["toppassword", "anothercommon"]);
        try
        {
            var validator = Build(path);
            var (valid, errors) = await validator.IsValidAsync("toppassword");
            valid.Should().BeFalse();
            errors.Should().ContainSingle().Which.Should().Contain("too common");
        }
        finally { File.Delete(path); }
    }

    // -------------------------------------------------------------------------
    // Case insensitivity
    // -------------------------------------------------------------------------

    [Fact]
    public async Task IsValid_DenyListMatchIsCaseInsensitive()
    {
        var path = WritePlainTempFile(["password"]);
        try
        {
            var validator = Build(path);
            (await validator.IsValidAsync("PASSWORD")).IsValid.Should().BeFalse();
            (await validator.IsValidAsync("Password")).IsValid.Should().BeFalse();
            (await validator.IsValidAsync("pAsSwOrD")).IsValid.Should().BeFalse();
        }
        finally { File.Delete(path); }
    }

    // -------------------------------------------------------------------------
    // Embedded resource
    // -------------------------------------------------------------------------

    [Fact]
    public async Task IsValid_EmbeddedSentinel_RejectsCommonPassword()
    {
        var validator = Build("embedded");
        var (valid, errors) = await validator.IsValidAsync("password");
        valid.Should().BeFalse();
        errors.Should().ContainSingle().Which.Should().Contain("too common");
    }

    [Fact]
    public async Task IsValid_EmbeddedSentinel_AcceptsStrongPassword()
    {
        var validator = Build("embedded");
        var (valid, errors) = await validator.IsValidAsync("Wr@ppedC0met#9x!");
        valid.Should().BeTrue();
        errors.Should().BeEmpty();
    }

    [Fact]
    public async Task IsValid_EmbeddedSentinel_CaseInsensitiveEmbeddedCheck()
    {
        var validator = Build("embedded");
        // "password" is in the embedded list; "PASSWORD" must also be rejected
        (await validator.IsValidAsync("PASSWORD")).IsValid.Should().BeFalse();
    }

    // -------------------------------------------------------------------------
    // IsPreviouslyUsed
    // -------------------------------------------------------------------------

    [Fact]
    public async Task IsPreviouslyUsed_AlwaysReturnsFalse()
    {
        var validator = Build(null);
        (await validator.IsPreviouslyUsedAsync("anything", [])).Should().BeFalse();
    }
}
