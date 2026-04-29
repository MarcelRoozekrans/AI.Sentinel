using ZeroAlloc.ValueObjects;

namespace AI.Sentinel.Domain;

[ValueObject]
public sealed partial class SessionId(string value)
{
    public string Value { get; } = string.IsNullOrWhiteSpace(value)
        ? throw new ArgumentException("SessionId must not be empty.", nameof(value))
        : value;
    public static SessionId New() => new(Guid.NewGuid().ToString("N"));
}
