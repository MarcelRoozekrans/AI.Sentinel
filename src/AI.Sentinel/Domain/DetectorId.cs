using ZeroAlloc.ValueObjects;

namespace AI.Sentinel.Domain;

[ValueObject]
public sealed partial class DetectorId(string value)
{
    public string Value { get; } = value;
    public override string ToString() => Value;
}
