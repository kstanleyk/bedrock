using Crestacle.Bedrock.Core.Interfaces.Services;

namespace Crestacle.Bedrock.Tests.Integration.Infrastructure;

/// <summary>Captures every published domain event so tests can assert on what actually fired.</summary>
internal sealed class CapturingEventPublisher : IBedrockEventPublisher
{
    private readonly List<object> _published = [];

    public IReadOnlyList<object> Published => _published;

    public Task PublishAsync<TEvent>(TEvent domainEvent, CancellationToken ct = default) where TEvent : class
    {
        _published.Add(domainEvent);
        return Task.CompletedTask;
    }
}
