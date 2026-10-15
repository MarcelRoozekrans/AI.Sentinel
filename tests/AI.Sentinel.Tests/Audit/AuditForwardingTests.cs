using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using Xunit;

namespace AI.Sentinel.Tests.Audit;

public class AuditForwardingTests
{
    [Fact]
    public async Task AppendAndForward_StillForwardsWhenTheCallerCancelsAfterTheAppend()
    {
        // The entry is already in the store; a client disconnect must not keep it from the SIEM.
        using var cts = new CancellationTokenSource();
        var store = new CancelAfterAppendStore(new RingBufferAuditStore(), cts);
        var forwarder = new TokenRecordingForwarder();

        var stored = await store.AppendAndForwardAsync(
            new AuditEntry("e1", DateTimeOffset.UtcNow, string.Empty, null, Severity.High, "SEC-01", "summary"),
            [forwarder], cts.Token);

        Assert.True(cts.IsCancellationRequested);
        var received = await forwarder.Received.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        Assert.Equal(stored, received.Entry);
        Assert.False(received.TokenCancelled);
    }

    private sealed class CancelAfterAppendStore(IAuditStore inner, CancellationTokenSource cts) : IAuditStore
    {
        public async ValueTask<AuditEntry> AppendAsync(AuditEntry entry, CancellationToken ct)
        {
            var stored = await inner.AppendAsync(entry, ct);
            await cts.CancelAsync();
            return stored;
        }

        public IAsyncEnumerable<AuditEntry> QueryAsync(AuditQuery query, CancellationToken ct) => inner.QueryAsync(query, ct);
    }

    private sealed class TokenRecordingForwarder : IAuditForwarder
    {
        public TaskCompletionSource<(AuditEntry Entry, bool TokenCancelled)> Received { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
        {
            Received.TrySetResult((batch[0], ct.IsCancellationRequested));
            return ValueTask.CompletedTask;
        }
    }
}
