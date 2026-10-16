using System.Text.Json;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using Xunit;

namespace AI.Sentinel.Tests.Audit;

[Collection("NonParallel")] // two tests swap Console.Error
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
            await f.SendAsync([MakeEntry("e1")], TestContext.Current.CancellationToken);
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
            await f.SendAsync([MakeEntry("e1"), MakeEntry("e2"), MakeEntry("e3")], TestContext.Current.CancellationToken);
        }

        var lines = File.ReadAllLines(_tempPath);
        Assert.Equal(3, lines.Length);
    }

    [Fact]
    public async Task SendAsync_NewlinesInSummary_EscapedNotBreakingFormat()
    {
        await using (var f = new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions { FilePath = _tempPath }))
        {
            await f.SendAsync([MakeEntry("e1", "line1\nline2\nline3")], TestContext.Current.CancellationToken);
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
            await f.SendAsync([MakeEntry("e1")], TestContext.Current.CancellationToken);
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
        await f.SendAsync([MakeEntry("e1")], TestContext.Current.CancellationToken);
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

                var send = f.SendAsync(batch, TestContext.Current.CancellationToken).AsTask();   // parks at FlushAsync, un-awaited
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
            Summary: "denied")
        {
            PolicyCode = "tenant_inactive",
        };

        await using (var f = new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions { FilePath = _tempPath }))
        {
            await f.SendAsync([entry], TestContext.Current.CancellationToken);
        }

        var lines = File.ReadAllLines(_tempPath);
        Assert.Single(lines);
        var parsed = JsonDocument.Parse(lines[0]);
        Assert.Equal("tenant_inactive", parsed.RootElement.GetProperty("PolicyCode").GetString());
    }

    [Fact]
    public async Task SendAsync_Failure_WithOnError_GoesToTheCallbackNotStderr()
    {
        var messages = new List<string>();
        var options = new NdjsonFileAuditForwarderOptions { FilePath = _tempPath, OnError = messages.Add };
        var stderr = await CaptureStderrAsync(async () =>
        {
            await using var f = new NdjsonFileAuditForwarder(options);
            using var cancelled = new CancellationTokenSource();
            await cancelled.CancelAsync();
            await f.SendAsync([MakeEntry("e1")], cancelled.Token);   // send_error
            await f.DisposeAsync();
            await f.SendAsync([MakeEntry("e2")], TestContext.Current.CancellationToken);   // send_dropped
        });

        Assert.Equal(2, messages.Count);
        Assert.Contains("action=send_error", messages[0], StringComparison.Ordinal);
        Assert.Contains("action=send_dropped", messages[1], StringComparison.Ordinal);
        Assert.DoesNotContain("audit_forward", stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SendAsync_Failure_WithoutOnError_WritesToStderr()
    {
        var stderr = await CaptureStderrAsync(async () =>
        {
            var f = new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions { FilePath = _tempPath });
            await f.DisposeAsync();
            await f.SendAsync([MakeEntry("e1")], TestContext.Current.CancellationToken);
        });

        Assert.Contains(
            "event=audit_forward action=send_dropped forwarder=NdjsonFile reason=disposed", stderr, StringComparison.Ordinal);
    }

    private static async Task<string> CaptureStderrAsync(Func<Task> action)
    {
        var previous = Console.Error;
        using var captured = new StringWriter();
        Console.SetError(captured);
        try
        {
            await action();
        }
        finally
        {
            Console.SetError(previous);
        }
        return captured.ToString();
    }
}
