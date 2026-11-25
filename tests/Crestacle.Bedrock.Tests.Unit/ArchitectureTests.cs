using System.Reflection;
using Crestacle.Bedrock.AspNetCore.Controllers;
using Crestacle.Bedrock.Core;
using Crestacle.Bedrock.EntityFramework;
using FluentAssertions;
using Xunit;

namespace Crestacle.Bedrock.Tests.Unit;

/// <summary>
/// Verifies the dependency flow Core ← EntityFramework ← AspNetCore is never violated for the
/// Bedrock assembly stack, mirroring Crestacle.Sentinel.Tests.ArchitectureTests for Sentinel.
/// These tests act as a compile-time safety net enforced at test-run time via reflection.
/// </summary>
public sealed class ArchitectureTests
{
    private static readonly Assembly CoreAssembly = typeof(BedrockErrorCodes).Assembly;

    // Use a public type from each upper layer to resolve its assembly name at runtime, so the
    // check stays correct even if the assembly name is ever changed.
    private static readonly string EfAssemblyName = typeof(BedrockContext).Assembly.GetName().Name!;
    private static readonly string AspNetCoreAssemblyName = typeof(BedrockAuthController).Assembly.GetName().Name!;

    [Fact]
    public void Core_DoesNotReference_BedrockEntityFramework()
    {
        var referenced = CoreAssembly
            .GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty);

        referenced.Should().NotContain(
            EfAssemblyName,
            $"Bedrock.Core must not depend on {EfAssemblyName}");
    }

    [Fact]
    public void Core_DoesNotReference_BedrockAspNetCore()
    {
        var referenced = CoreAssembly
            .GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty);

        referenced.Should().NotContain(
            AspNetCoreAssemblyName,
            $"Bedrock.Core must not depend on {AspNetCoreAssemblyName}");
    }

    [Fact]
    public void EntityFramework_DoesNotReference_BedrockAspNetCore()
    {
        var referenced = typeof(BedrockContext).Assembly
            .GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty);

        referenced.Should().NotContain(
            AspNetCoreAssemblyName,
            $"Bedrock.EntityFramework must not depend on {AspNetCoreAssemblyName}");
    }
}
