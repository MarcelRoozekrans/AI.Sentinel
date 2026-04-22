using ZeroAlloc.Validation;

namespace AI.Sentinel;

public sealed class SentinelOptionsValidator
{
    public ValidationResult Validate(SentinelOptions opts)
    {
        var failures = new List<ValidationFailure>();

        if (opts.AuditCapacity <= 0)
            failures.Add(new ValidationFailure
            {
                ErrorMessage = "AuditCapacity must be greater than 0",
                ErrorCode    = "GreaterThan"
            });

        if (opts.MaxCallsPerSecond is int mps && mps <= 0)
            failures.Add(new ValidationFailure
            {
                ErrorMessage = "MaxCallsPerSecond must be greater than 0",
                ErrorCode    = "GreaterThan"
            });

        if (opts.BurstSize is int bs && bs <= 0)
            failures.Add(new ValidationFailure
            {
                ErrorMessage = "BurstSize must be greater than 0",
                ErrorCode    = "GreaterThan"
            });

        if (opts.SessionIdleTimeout <= TimeSpan.Zero)
            failures.Add(new ValidationFailure
            {
                ErrorMessage = "SessionIdleTimeout must be greater than TimeSpan.Zero",
                ErrorCode    = "GreaterThan"
            });

        return new ValidationResult([.. failures]);
    }
}
