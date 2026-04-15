using ZeroAlloc.ValueObjects;

namespace AI.Sentinel.Domain;

[ValueObject]
public sealed partial class SessionId(string value)
{
    public string Value { get; } = value;
    public static SessionId New() => new(Guid.NewGuid().ToString("N"));
    public override string ToString() => Value;
}
