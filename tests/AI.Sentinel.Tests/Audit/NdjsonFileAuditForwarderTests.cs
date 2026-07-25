using System.Text.Json;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using Xunit;

namespace AI.Sentinel.Tests.Audit;

public class NdjsonFileAuditForwarderTests : IDisposable
{
    private readonly string _tempPath = Path.Combine(Path.GetTempPath(), $"sentinel-{Guid.NewGuid():N}.ndjson");

    public void Dispose()
    {
        try
        {
            File.Delete(_tempPath);
        }
        catch (IOException)
        {
            // best effort cleanup
        }
        catch (UnauthorizedAccessException)
        {
            // best effort cleanup
        }
        GC.SuppressFinalize(this);
    }

    private static AuditEntry MakeEntry(string id, string summary = "test") =>
        new(id, DateTimeOffset.UtcNow, "h", null, Severity.Low, "T-01", summary);

    [Fact]
    public async Task SendAsync_AppendsLineToFile()
    {
        await using (var f = new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions { FilePath = _tempPath }))
        {
            await f.SendAsync([MakeEntry("e1")], default);
        }

        var lines = File.ReadAllLines(_tempPath);
        Assert.Single(lines);
        var parsed = JsonDocument.Parse(lines[0]);
        Assert.Equal("e1", parsed.RootElement.GetProperty("Id").GetString());
    }

    [Fact]
    public async Task SendAsync_MultipleEntries_OneLinePerEntry()
    {
        await using (var f = new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions { FilePath = _tempPath }))
        {
            await f.SendAsync([MakeEntry("e1"), MakeEntry("e2"), MakeEntry("e3")], default);
        }

        var lines = File.ReadAllLines(_tempPath);
        Assert.Equal(3, lines.Length);
    }

    [Fact]
    public async Task SendAsync_NewlinesInSummary_EscapedNotBreakingFormat()
    {
        await using (var f = new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions { FilePath = _tempPath }))
        {
            await f.SendAsync([MakeEntry("e1", "line1\nline2\nline3")], default);
        }

        var lines = File.ReadAllLines(_tempPath);
        Assert.Single(lines);
        var parsed = JsonDocument.Parse(lines[0]);
        Assert.Equal("line1\nline2\nline3", parsed.RootElement.GetProperty("Summary").GetString());
    }

    [Fact]
    public async Task SendAsync_AppendMode_PreservesPriorContent()
    {
        File.WriteAllText(_tempPath, "{\"existing\":\"line\"}\n");

        await using (var f = new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions { FilePath = _tempPath }))
        {
            await f.SendAsync([MakeEntry("e1")], default);
        }

        var lines = File.ReadAllLines(_tempPath);
        Assert.Equal(2, lines.Length);
        Assert.Contains("existing", lines[0], StringComparison.Ordinal);
    }

    [Fact]
    public async Task SendAsync_AfterDispose_DoesNotThrow()
    {
        var f = new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions { FilePath = _tempPath });
        await f.DisposeAsync();
        // After dispose, writing should NOT throw — the IAuditForwarder contract says MUST NOT throw.
        // SendAsync now drops the batch (fail-open) instead of writing to the closed stream.
        await f.SendAsync([MakeEntry("e1")], default);
    }

    [Fact]
    public async Task DisposeAsync_ConcurrentWithInFlightSend_DoesNotThrow()
    {
        // Regression for #105. DisposeAsync used to close the FileStream without taking the
        // write lock, so _writer.DisposeAsync (which flushes) ran concurrently with an
        // in-flight SendAsync write and threw
        //   InvalidOperationException: The stream is currently in use by a previous operation on the stream.
        // — escaping DisposeAsync (SendAsync swallows its own exceptions, DisposeAsync did not).
        //
        // Reliable repro: a large batch makes SendAsync park at its async FlushAsync (the
        // buffered WriteLineAsync calls mostly complete synchronously into the StreamWriter
        // buffer), so `send` is genuinely mid-flush on the FileStream when DisposeAsync fires
        // on this thread. Looping tightens the window. Verified to throw on the pre-fix code
        // and pass after.
        // Same payload every iteration — build it once (also keeps the ZeroAlloc analyzer happy).
        var batch = new AuditEntry[5_000];
        for (var i = 0; i < batch.Length; i++)
        {
            batch[i] = MakeEntry($"e{i}");
        }

        for (var iter = 0; iter < 40; iter++)
        {
            var path = Path.Combine(Path.GetTempPath(), $"sentinel-race-{Guid.NewGuid():N}.ndjson");
            try
            {
                var f = new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions { FilePath = path });

                var send = f.SendAsync(batch, default).AsTask();   // parks at FlushAsync, un-awaited
                await f.DisposeAsync();                            // races the in-flight flush — must NOT throw
                await send;                                        // fail-open: never throws

                await f.DisposeAsync();                            // idempotent — not ObjectDisposedException
            }
            finally
            {
                try { File.Delete(path); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            }
        }
    }

    [Fact]
    public async Task SendAsync_PolicyCode_PropagatesIntoSerializedJson()
    {
        var entry = new AuditEntry(
            Id: "authz-1",
            Timestamp: DateTimeOffset.UtcNow,
            Hash: "h",
            PreviousHash: null,
            Severity: Severity.High,
            DetectorId: "AUTHZ-DENY",
            Summary: "denied",
            PolicyCode: "tenant_inactive");

        await using (var f = new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions { FilePath = _tempPath }))
        {
            await f.SendAsync([entry], default);
        }

        var lines = File.ReadAllLines(_tempPath);
        Assert.Single(lines);
        var parsed = JsonDocument.Parse(lines[0]);
        Assert.Equal("tenant_inactive", parsed.RootElement.GetProperty("PolicyCode").GetString());
    }
}
