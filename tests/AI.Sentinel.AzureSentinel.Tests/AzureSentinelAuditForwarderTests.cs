using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using Azure;
using Xunit;

namespace AI.Sentinel.AzureSentinel.Tests;

public sealed class AzureSentinelAuditForwarderTests
{
    private static AuditEntry MakeEntry(string id) =>
        new(id, DateTimeOffset.UtcNow, $"h-{id}", null, Severity.High, "SEC-01", $"summary-{id}");

    [Fact]
    public async Task SendAsync_CallsUploadOnce_WithCorrectBatch()
    {
        var stub = new RecordingClient();
        var f = new AzureSentinelAuditForwarder(stub, new AzureSentinelAuditForwarderOptions
        {
            DcrEndpoint = new Uri("https://dce.example.com"),
            DcrImmutableId = "dcr-abc",
            StreamName = "Custom-AISentinelAudit_CL",
        });

        await f.SendAsync(new[] { MakeEntry("e1"), MakeEntry("e2") }, default);

        Assert.Single(stub.Uploads);
        Assert.Equal("dcr-abc", stub.Uploads[0].RuleId);
        Assert.Equal("Custom-AISentinelAudit_CL", stub.Uploads[0].StreamName);
        Assert.Equal(2, stub.Uploads[0].Count);
    }

    [Fact]
    public async Task SendAsync_RequestFailedException_Swallowed_NotPropagated()
    {
        var stub = new ThrowingClient();
        var f = new AzureSentinelAuditForwarder(stub, new AzureSentinelAuditForwarderOptions
        {
            DcrEndpoint = new Uri("https://dce.example.com"),
            DcrImmutableId = "dcr-abc",
            StreamName = "Custom-AISentinelAudit_CL",
        });

        // Must not throw.
        await f.SendAsync(new[] { MakeEntry("e1") }, default);
    }

    [Fact]
    public void Construction_MissingDcrImmutableId_Throws()
    {
        var stub = new RecordingClient();
        Assert.Throws<ArgumentException>(() => new AzureSentinelAuditForwarder(stub, new AzureSentinelAuditForwarderOptions
        {
            DcrEndpoint = new Uri("https://dce.example.com"),
            DcrImmutableId = "",
            StreamName = "stream",
        }));
    }

    private sealed class RecordingClient : ILogsIngestionClientWrapper
    {
        public List<(string RuleId, string StreamName, int Count)> Uploads { get; } = new();

        public Task UploadAsync(string ruleId, string streamName, IEnumerable<AuditEntry> entries, CancellationToken ct)
        {
            Uploads.Add((ruleId, streamName, entries.Count()));
            return Task.CompletedTask;
        }
    }

    private sealed class ThrowingClient : ILogsIngestionClientWrapper
    {
        public Task UploadAsync(string ruleId, string streamName, IEnumerable<AuditEntry> entries, CancellationToken ct)
            => throw new RequestFailedException("boom");
    }
}
