using AI.Sentinel.Audit;

namespace AI.Sentinel.Benchmarks.Harness;

/// <summary>
/// No-op <see cref="IAuditForwarder"/> used to isolate pipeline-side forwarder
/// dispatch cost (allocation + <see cref="Task.Run"/> per entry per forwarder)
/// from any real I/O. <see cref="SendAsync"/> returns a completed
/// <see cref="ValueTask"/> so the only cost measured is what the pipeline
/// itself pays to fan out an audit entry.
/// </summary>
internal sealed class MockAuditForwarder : IAuditForwarder
{
    public ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
        => ValueTask.CompletedTask;
}
