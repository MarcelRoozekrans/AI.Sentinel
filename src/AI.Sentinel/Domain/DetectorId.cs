using ZeroAlloc.ValueObjects;

namespace AI.Sentinel.Domain;

[ValueObject]
public sealed partial class DetectorId(string value)
{
    public string Value { get; } = string.IsNullOrWhiteSpace(value)
        ? throw new ArgumentException("DetectorId must not be empty.", nameof(value))
        : value;
}
