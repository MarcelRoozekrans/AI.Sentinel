using ZeroAlloc.ValueObjects;

namespace AI.Sentinel.Domain;

[ValueObject]
public sealed partial class AgentId(string value)
{
    public string Value { get; } = string.IsNullOrWhiteSpace(value)
        ? throw new ArgumentException("AgentId must not be empty.", nameof(value))
        : value;
}
