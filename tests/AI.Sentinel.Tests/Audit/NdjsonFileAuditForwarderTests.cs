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
        foreach (var path in new[] { _tempPath, _tempPath + ".lock" })
        {
            try
            {
                File.Delete(path);
            }
            catch (IOException)
            {
                // best effort cleanup
            }
            catch (UnauthorizedAccessException)
            {
                // best effort cleanup
            }
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

    [Fact]
    public async Task ConcurrentForwarders_OnOneFile_AppendEveryBatchIntact()
    {
        // Each forwarder holds its own FileStream, as separate processes do. With a share mode that
        // denies other writers the second constructor throws on Windows; with one that allows them but
        // a position fixed at open, writers overwrite each other's lines on every platform.
        const int Writers = 6;
        const int Batches = 40;
        const int BatchSize = 5;
        var forwarders = new NdjsonFileAuditForwarder[Writers];
        var errors = new System.Collections.Concurrent.ConcurrentQueue<string>();
        for (var w = 0; w < Writers; w++)
        {
            forwarders[w] = new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions
            {
                FilePath = _tempPath,
                LockTimeout = TimeSpan.FromSeconds(60),
                OnError = errors.Enqueue,
            });
        }

        try
        {
            await Task.WhenAll(Enumerable.Range(0, Writers).Select(w => Task.Run(async () =>
            {
                for (var b = 0; b < Batches; b++)
                {
                    await forwarders[w].SendAsync(MakeBatch($"w{w}", b, BatchSize), TestContext.Current.CancellationToken);
                }
            }, TestContext.Current.CancellationToken)));
        }
        finally
        {
            foreach (var f in forwarders) await f.DisposeAsync();
        }

        Assert.Empty(errors);
        AssertBatchesIntact(File.ReadAllLines(_tempPath), Enumerable.Range(0, Writers).Select(w => $"w{w}"), Batches, BatchSize);
    }

    [Fact]
    public async Task SeveralProcesses_OnOneFile_AppendEveryBatchIntact()
    {
        const int Processes = 4;
        const int Batches = 50;
        const int BatchSize = 8;
        var startFile = _tempPath + ".start";
        var helper = Path.Combine(AppContext.BaseDirectory, "AI.Sentinel.Tests.NdjsonWriter.dll");
        Assert.True(File.Exists(helper), $"writer helper not found at {helper}");

        var processes = new List<System.Diagnostics.Process>();
        try
        {
            for (var p = 0; p < Processes; p++)
            {
                var psi = new System.Diagnostics.ProcessStartInfo(DotnetHost())
                {
                    RedirectStandardError = true,
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                };
                foreach (var arg in new[] { "exec", helper, _tempPath, $"p{p}", $"{Batches}", $"{BatchSize}", startFile })
                {
                    psi.ArgumentList.Add(arg);
                }
                processes.Add(System.Diagnostics.Process.Start(psi)!);
            }

            // Release every writer at once so their appends overlap.
            await File.WriteAllTextAsync(startFile, "go", TestContext.Current.CancellationToken);

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
            timeout.CancelAfter(TimeSpan.FromMinutes(2));
            foreach (var process in processes)
            {
                var stderr = process.StandardError.ReadToEndAsync(timeout.Token);
                await process.WaitForExitAsync(timeout.Token);
                Assert.True(process.ExitCode == 0, $"writer exited with {process.ExitCode}: {await stderr}");
            }
        }
        finally
        {
            foreach (var process in processes)
            {
                if (!process.HasExited) process.Kill(entireProcessTree: true);
                process.Dispose();
            }
            try { File.Delete(startFile); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }

        AssertBatchesIntact(File.ReadAllLines(_tempPath), Enumerable.Range(0, Processes).Select(p => $"p{p}"), Batches, BatchSize);
    }

    [Fact]
    public async Task LockHeldElsewhere_SendTimesOut_ReportsAndDropsTheBatch()
    {
        var messages = new System.Collections.Concurrent.ConcurrentQueue<string>();
        await using var f = new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions
        {
            FilePath = _tempPath,
            LockTimeout = TimeSpan.FromMilliseconds(200),
            OnError = messages.Enqueue,
        });

        // Another writer holds the lock, for example a hung process.
        using (new FileStream(_tempPath + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
        {
            await f.SendAsync([MakeEntry("dropped")], TestContext.Current.CancellationToken);
        }

        var message = Assert.Single(messages);
        Assert.Contains("action=send_error", message, StringComparison.Ordinal);
        Assert.Contains("error=TimeoutException", message, StringComparison.Ordinal);
        Assert.Empty(File.ReadAllLines(_tempPath));

        // The lock is free again, and so is the forwarder.
        await f.SendAsync([MakeEntry("e1")], TestContext.Current.CancellationToken);
        Assert.Equal("e1", JsonDocument.Parse(Assert.Single(File.ReadAllLines(_tempPath))).RootElement.GetProperty("Id").GetString());
    }

    [Fact]
    public async Task SendAsync_WriteFailsUnderTheLock_ReleasesTheLock()
    {
        var messages = new System.Collections.Concurrent.ConcurrentQueue<string>();
        await using var f = new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions
        {
            FilePath = _tempPath,
            OnError = messages.Enqueue,
        });

        // Replace the file with a directory: the append under the lock now throws.
        File.Delete(_tempPath);
        Directory.CreateDirectory(_tempPath);
        try
        {
            await f.SendAsync([MakeEntry("e1")], TestContext.Current.CancellationToken);
            Assert.Contains("action=send_error", Assert.Single(messages), StringComparison.Ordinal);

            // Opening the lock exclusively succeeds only if the failed send released it.
            using var held = new FileStream(_tempPath + ".lock", FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        }
        finally
        {
            Directory.Delete(_tempPath);
        }
    }

    [Fact]
    public async Task File_IsReadableAndDeletableWhileTheForwarderIsOpen()
    {
        await using var f = new NdjsonFileAuditForwarder(new NdjsonFileAuditForwarderOptions { FilePath = _tempPath });
        await f.SendAsync([MakeEntry("e1")], TestContext.Current.CancellationToken);

        // A log shipper reads, and log rotation renames or deletes, while the writer lives.
        Assert.Single(File.ReadAllLines(_tempPath));
        File.Delete(_tempPath);

        await f.SendAsync([MakeEntry("e2")], TestContext.Current.CancellationToken);
        Assert.Equal("e2", JsonDocument.Parse(Assert.Single(File.ReadAllLines(_tempPath))).RootElement.GetProperty("Id").GetString());
    }

    private static AuditEntry[] MakeBatch(string writer, int batch, int size)
    {
        var entries = new AuditEntry[size];
        for (var i = 0; i < size; i++)
        {
            entries[i] = MakeEntry($"{writer}-{batch}-{i}", new string('x', 512));
        }
        return entries;
    }

    /// <summary>Every line parses as JSON, every batch is present exactly once as one contiguous run of lines
    /// in entry order, and each writer's batches appear in the order it sent them.</summary>
    private static void AssertBatchesIntact(string[] lines, IEnumerable<string> writers, int batches, int batchSize)
    {
        var writerList = writers.ToList();
        Assert.Equal(writerList.Count * batches * batchSize, lines.Length);

        var ids = lines.Select(line => JsonDocument.Parse(line).RootElement.GetProperty("Id").GetString()!).ToArray();
        var nextBatch = writerList.ToDictionary(w => w, _ => 0, StringComparer.Ordinal);
        for (var start = 0; start < ids.Length; start += batchSize)
        {
            var writer = ids[start][..ids[start].IndexOf('-', StringComparison.Ordinal)];
            Assert.True(nextBatch.TryGetValue(writer, out var batch), $"unexpected writer in '{ids[start]}'");
            for (var i = 0; i < batchSize; i++)
            {
                Assert.Equal($"{writer}-{batch}-{i}", ids[start + i]);
            }
            nextBatch[writer] = batch + 1;
        }
        Assert.All(nextBatch.Values, n => Assert.Equal(batches, n));
    }

    /// <summary>The dotnet host running this test, so the child runs on the same runtime install.</summary>
    private static string DotnetHost()
    {
        var host = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH");
        if (!string.IsNullOrEmpty(host) && File.Exists(host)) return host;
        var current = Environment.ProcessPath;
        if (current is not null && Path.GetFileNameWithoutExtension(current).Equals("dotnet", StringComparison.OrdinalIgnoreCase)) return current;
        return "dotnet";
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
