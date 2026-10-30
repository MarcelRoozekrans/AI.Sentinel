using AI.Sentinel.Domain;

namespace AI.Sentinel.Detection;

/// <summary>A reviewer's answer.</summary>
/// <param name="Severity">The severity the reviewer gives, or <see langword="null"/> when it gave no usable verdict.</param>
/// <param name="Reason">The reviewer's reason, empty when there is none.</param>
public sealed record ReviewVerdict(Severity? Severity, string Reason)
{
    /// <summary>No verdict: the reviewer's answer could not be read.</summary>
    public static ReviewVerdict None { get; } = new(null, string.Empty);
}
