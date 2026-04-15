using ZeroAlloc.ValueObjects;

namespace AI.Sentinel.Domain;

[ValueObject]
public sealed partial class AgentId(string value)
{
    public string Value { get; } = value;
    public override string ToString() => Value;
}
