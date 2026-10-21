using AI.Sentinel.Audit;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AI.Sentinel.Tests.Audit;

public class PipelineForwarderIntegrationTests
{
    [Fact]
    public async Task AuditAppend_InvokesForwarderWithSingleEntryBatch()
    {
        var fwd = new RecordingAuditForwarder();
        var sp = BuildProvider(fwd);

        var client = new ChatClientBuilder(new EchoChatClient()).UseAISentinel().Build(sp);
        await client.GetResponseAsync([new ChatMessage(ChatRole.User, "hello")], default, TestContext.Current.CancellationToken);

        // Each stored entry is forwarded on its own fire-and-forget task, so wait for all of them
        // rather than for the first: a later one may still be landing while the test asserts.
        var stored = await RecordingAuditForwarder.ReadAllAsync(sp.GetRequiredService<IAuditStore>());
        Assert.NotEmpty(stored);
        await fwd.WaitForAsync(stored.Count);

        var batches = fwd.Batches;
        Assert.Equal(stored.Count, batches.Count);
        Assert.All(batches, b => Assert.Single(b)); // single-entry batches
    }

    [Fact]
    public async Task ForwardedEntries_AreTheEntriesAsStored()
    {
        // Forwarders must receive the chain hashes the store assigned, or a SIEM cannot verify them.
        var fwd = new RecordingAuditForwarder();
        var sp = BuildProvider(fwd);

        var client = new ChatClientBuilder(new EchoChatClient()).UseAISentinel().Build(sp);
        await client.GetResponseAsync([new ChatMessage(ChatRole.User, "hello")], default, TestContext.Current.CancellationToken);

        var stored = await RecordingAuditForwarder.ReadAllAsync(sp.GetRequiredService<IAuditStore>());
        Assert.NotEmpty(stored);
        await fwd.WaitForAsync(stored.Count);
        // Forwarding order across entries is not part of the contract: each entry runs on its own task.
        Assert.Equal(
            stored.OrderBy(e => e.Id, StringComparer.Ordinal),
            fwd.Entries.OrderBy(e => e.Id, StringComparer.Ordinal));
    }

    [Fact]
    public async Task MultipleForwarders_AllReceiveEntry()
    {
        var fwdA = new RecordingAuditForwarder();
        var fwdB = new RecordingAuditForwarder();
        var sp = BuildProvider(fwdA, fwdB);

        var client = new ChatClientBuilder(new EchoChatClient()).UseAISentinel().Build(sp);
        await client.GetResponseAsync([new ChatMessage(ChatRole.User, "hello")], default, TestContext.Current.CancellationToken);

        var stored = await RecordingAuditForwarder.ReadAllAsync(sp.GetRequiredService<IAuditStore>());
        Assert.NotEmpty(stored);
        await fwdA.WaitForAsync(stored.Count);
        await fwdB.WaitForAsync(stored.Count);

        Assert.Equal(stored.Count, fwdA.Entries.Count);
        Assert.Equal(stored.Count, fwdB.Entries.Count);
    }

    [Fact]
    public async Task NoForwardersRegistered_PipelineWorksUnchanged()
    {
        var sp = BuildProvider();

        var client = new ChatClientBuilder(new EchoChatClient()).UseAISentinel().Build(sp);
        var response = await client.GetResponseAsync([new ChatMessage(ChatRole.User, "hello")], default, TestContext.Current.CancellationToken);

        Assert.NotNull(response);
    }

    [Fact]
    public async Task NdjsonForwarder_PlusRecordingForwarder_BothReceiveEntry_ViaRealDI()
    {
        // Already covered: 2 recording forwarders. New angle: NdjsonFileAuditForwarder (real impl) + a recording one.
        var ndjsonPath = Path.Combine(Path.GetTempPath(), $"sentinel-fanout-{Guid.NewGuid():N}.ndjson");
        try
        {
            var recording = new RecordingAuditForwarder();
            var services = new ServiceCollection();
            services.AddAISentinel(opts => { });
            services.AddSentinelNdjsonFileForwarder(opts => opts.FilePath = ndjsonPath);
            services.AddSingleton<IAuditForwarder>(recording);
            var sp = services.BuildServiceProvider();

            var client = new ChatClientBuilder(new EchoChatClient()).UseAISentinel().Build(sp);
            await client.GetResponseAsync([new ChatMessage(ChatRole.User, "hello")], default, TestContext.Current.CancellationToken);

            var stored = await RecordingAuditForwarder.ReadAllAsync(sp.GetRequiredService<IAuditStore>());
            Assert.NotEmpty(stored);
            await recording.WaitForAsync(stored.Count);

            // Both forwarders run fire-and-forget on Task.Run. Wait until every stored entry is in
            // the file before disposing the provider: a send that starts after DisposeAsync is
            // dropped by the fail-open contract and the file would come up short. The file has no
            // completion signal, so this one wait polls it; the bound is a hang detector.
            await WaitForLinesAsync(ndjsonPath, stored.Count);

            await ((IAsyncDisposable)sp).DisposeAsync();
            Assert.Equal(stored.Count, File.ReadAllLines(ndjsonPath).Length);
        }
        finally
        {
            foreach (var path in new[] { ndjsonPath, ndjsonPath + ".lock" })
            {
                try { File.Delete(path); }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }

    [Fact]
    public async Task SlowForwarder_DoesNotBlockPipeline()
    {
        // The invariant is "the pipeline did not await the forwarder". The forwarder blocks until the
        // test releases it, so the call can only complete if the pipeline did not wait for it. A
        // wall-clock threshold, or a forwarder that finishes on its own after a delay, would make the
        // result depend on how loaded the machine is.
        var slow = new BlockingForwarder();
        var sp = BuildProvider(slow);

        var client = new ChatClientBuilder(new EchoChatClient()).UseAISentinel().Build(sp);
        try
        {
            await client.GetResponseAsync([new ChatMessage(ChatRole.User, "hello")], default, TestContext.Current.CancellationToken)
                .WaitAsync(RecordingAuditForwarder.DefaultWaitTimeout, TestContext.Current.CancellationToken);

            await slow.Started.WaitAsync(RecordingAuditForwarder.DefaultWaitTimeout, TestContext.Current.CancellationToken);
            Assert.False(slow.Completed, "the pipeline awaited the slow forwarder");
        }
        finally
        {
            slow.Release();
        }
    }

    private static ServiceProvider BuildProvider(params IAuditForwarder[] forwarders)
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => { });
        foreach (var forwarder in forwarders)
        {
            services.AddSingleton(forwarder);
        }
        return services.BuildServiceProvider();
    }

    /// <summary>Polls <paramref name="path"/> until it holds <paramref name="count"/> lines.
    /// Reads with a share mode that lets the forwarder keep writing.</summary>
    private static async Task WaitForLinesAsync(string path, int count)
    {
        var deadline = DateTime.UtcNow + RecordingAuditForwarder.DefaultWaitTimeout;
        var lines = 0;
        while (DateTime.UtcNow < deadline)
        {
            if (File.Exists(path))
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var reader = new StreamReader(stream);
                var text = await reader.ReadToEndAsync(TestContext.Current.CancellationToken);
                lines = text.AsSpan().Count('\n');
                if (lines >= count) return;
            }
            await Task.Delay(25, TestContext.Current.CancellationToken);
        }
        throw new TimeoutException($"Expected {count} lines in {path}, found {lines}.");
    }

    private sealed class BlockingForwarder : IAuditForwarder
    {
        private readonly TaskCompletionSource _started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private volatile bool _completed;

        public Task Started => _started.Task;
        public bool Completed => _completed;

        public void Release() => _release.TrySetResult();

        public async ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
        {
            _started.TrySetResult();
            await _release.Task;
            _completed = true;
        }
    }

    private sealed class EchoChatClient : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> m, ChatOptions? o = null, CancellationToken ct = default)
            => Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, "ok")));
        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> m, ChatOptions? o = null, CancellationToken ct = default) => throw new NotSupportedException();
        public object? GetService(Type serviceType, object? serviceKey = null) => null;
        public void Dispose() { }
    }
}
