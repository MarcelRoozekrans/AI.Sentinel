using ZeroAlloc.Validation;

namespace AI.Sentinel;

/// <summary>Validation rule: the <see cref="TimeSpan"/> property must be strictly greater than <see cref="TimeSpan.Zero"/>.</summary>
[RuleMessage("{PropertyName} must be greater than TimeSpan.Zero.", ErrorCode = "GreaterThan")]
[AttributeUsage(AttributeTargets.Property, AllowMultiple = false)]
internal sealed class PositiveTimeSpanAttribute : ValidationAttribute<TimeSpan>
{
    public override bool IsValid(TimeSpan value) => value > TimeSpan.Zero;
}
