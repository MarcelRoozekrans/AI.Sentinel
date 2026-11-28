using AI.Sentinel.Audit;

namespace AI.Sentinel.ClaudeCode.Events;

/// <summary>One page of the local audit after a sequence. <paramref name="First"/> and <paramref name="Last"/> are the smallest and
/// largest sequence the audit holds now, or 0 when it is empty. <paramref name="FileId"/> names the audit file, and
/// <paramref name="LastAssigned"/> is the last sequence it handed out, also when retention deleted that entry since (#713).</summary>
internal sealed record AuditPage(
    IReadOnlyList<(long Sequence, AuditEntry Entry)> Rows, long First, long Last, string? FileId = null, long LastAssigned = 0)
{
    /// <summary>The audit could not be read now, for instance because it is busy or not there. This is not an empty audit: the
    /// forwarder must keep its cursor and try again.</summary>
    public static readonly AuditPage Unreadable = new([], 0, 0) { ReadFailed = true };

    /// <summary>True when the audit could not be read; <see cref="Rows"/> says nothing then.</summary>
    public bool ReadFailed { get; init; }
}
