using ZeroAlloc.Validation;

namespace AI.Sentinel;

public sealed class SentinelOptionsValidator
{
    public ValidationResult Validate(SentinelOptions opts)
    {
        if (opts.AuditCapacity <= 0)
            return new ValidationResult([new ValidationFailure
            {
                ErrorMessage = "AuditCapacity must be greater than 0",
                ErrorCode    = "GreaterThan"
            }]);
        return new ValidationResult([]);
    }
}
