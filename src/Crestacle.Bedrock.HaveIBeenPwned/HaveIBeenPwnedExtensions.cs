using Crestacle.Bedrock.AspNetCore;
using Crestacle.Bedrock.AspNetCore.Services;
using Crestacle.Bedrock.Core.Interfaces.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Crestacle.Bedrock.HaveIBeenPwned;

/// <summary>Fluent extensions for wiring the Have I Been Pwned password validator into a Bedrock builder.</summary>
public static class HaveIBeenPwnedExtensions
{
    /// <summary>
    /// Wraps whatever <see cref="IPasswordValidator"/> is currently registered (the Bedrock
    /// default, or a caller's own custom complexity rules registered before this call) with
    /// <see cref="HaveIBeenPwnedPasswordValidator"/>, which additionally rejects passwords found
    /// in known data breaches. The wrapped validator's own rules still run -- this does not
    /// replace them.
    /// </summary>
    /// <remarks>
    /// The HIBP API is called with k-anonymity (only the first 5 SHA-1 hex characters are sent).
    /// The validator is fail-open: if the API is unreachable, the password is accepted.
    /// </remarks>
    public static IBedrockBuilder WithHaveIBeenPwnedPasswordValidator(this IBedrockBuilder builder)
    {
        builder.Services.AddHttpClient("hibp", client =>
        {
            client.BaseAddress = new Uri("https://api.pwnedpasswords.com");
            client.Timeout = TimeSpan.FromSeconds(3);
            client.DefaultRequestHeaders.Add("User-Agent", "Crestacle.Bedrock");
        });

        var existing = builder.Services
            .FirstOrDefault(d => d.ServiceType == typeof(IPasswordValidator));
        if (existing is not null)
            builder.Services.Remove(existing);

        // Capture whatever was previously registered as IPasswordValidator -- the Bedrock
        // default, or a caller's own custom complexity rules registered before this call -- so
        // it keeps running as the inner validator instead of being silently discarded in favor
        // of a hardcoded DefaultPasswordValidator.
        Func<IServiceProvider, object> innerFactory = existing switch
        {
            { ImplementationFactory: not null } d => d.ImplementationFactory,
            { ImplementationInstance: not null } d => _ => d.ImplementationInstance,
            { ImplementationType: not null } d => sp => ActivatorUtilities.CreateInstance(sp, d.ImplementationType),
            _ => sp => sp.GetRequiredService<DefaultPasswordValidator>(),
        };

        // Safety net for the fallback branch above (no prior IPasswordValidator registration at
        // all, which shouldn't happen given AddBedrockAspNetCore's own TryAdd default, but this
        // extension shouldn't assume call order).
        builder.Services.TryAddScoped<DefaultPasswordValidator>();

        builder.Services.AddScoped<IPasswordValidator>(sp =>
            new HaveIBeenPwnedPasswordValidator(
                sp.GetRequiredService<IHttpClientFactory>(),
                (IPasswordValidator)innerFactory(sp)));

        return builder;
    }
}
