using AI.Sentinel.Audit;

namespace AI.Sentinel.ClaudeCode.Events;

/// <summary>One page of the local audit after a sequence. <paramref name="First"/> and <paramref name="Last"/> are the smallest and
/// largest sequence the audit holds now, or 0 when it is empty.</summary>
internal sealed record AuditPage(IReadOnlyList<(long Sequence, AuditEntry Entry)> Rows, long First, long Last)
{
    public static readonly AuditPage Empty = new([], 0, 0);
}
