using AI.Sentinel.Audit;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AI.Sentinel.Tests.Audit;

public class PipelineForwarderIntegrationTests
{
    [Fact]
    public async Task AuditAppend_InvokesForwarderWithSingleEntryBatch()
    {
        var fwd = new RecordingForwarder();
        var services = new ServiceCollection();
        services.AddAISentinel(opts => { });
        services.AddSingleton<IAuditForwarder>(fwd);
        var sp = services.BuildServiceProvider();

        var client = new ChatClientBuilder(new EchoChatClient()).UseAISentinel().Build(sp);
        await client.GetResponseAsync([new ChatMessage(ChatRole.User, "hello")]);

        // Wait for fire-and-forget propagation
        await Task.Delay(100);

        Assert.NotEmpty(fwd.Batches);
        Assert.All(fwd.Batches, b => Assert.Single(b)); // single-entry batches
    }

    [Fact]
    public async Task MultipleForwarders_AllReceiveEntry()
    {
        var fwdA = new RecordingForwarder();
        var fwdB = new RecordingForwarder();
        var services = new ServiceCollection();
        services.AddAISentinel(opts => { });
        services.AddSingleton<IAuditForwarder>(fwdA);
        services.AddSingleton<IAuditForwarder>(fwdB);
        var sp = services.BuildServiceProvider();

        var client = new ChatClientBuilder(new EchoChatClient()).UseAISentinel().Build(sp);
        await client.GetResponseAsync([new ChatMessage(ChatRole.User, "hello")]);
        await Task.Delay(100);

        Assert.NotEmpty(fwdA.Batches);
        Assert.NotEmpty(fwdB.Batches);
    }

    [Fact]
    public async Task NoForwardersRegistered_PipelineWorksUnchanged()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(opts => { });
        var sp = services.BuildServiceProvider();

        var client = new ChatClientBuilder(new EchoChatClient()).UseAISentinel().Build(sp);
        var response = await client.GetResponseAsync([new ChatMessage(ChatRole.User, "hello")]);

        Assert.NotNull(response);
    }

    [Fact]
    public async Task NdjsonForwarder_PlusRecordingForwarder_BothReceiveEntry_ViaRealDI()
    {
        // Already covered: 2 RecordingForwarders. New angle: NdjsonFileAuditForwarder (real impl) + RecordingForwarder.
        var ndjsonPath = Path.Combine(Path.GetTempPath(), $"sentinel-fanout-{Guid.NewGuid():N}.ndjson");
        try
        {
            var recording = new RecordingForwarder();
            var services = new ServiceCollection();
            services.AddAISentinel(opts => { });
            services.AddSentinelNdjsonFileForwarder(opts => opts.FilePath = ndjsonPath);
            services.AddSingleton<IAuditForwarder>(recording);
            var sp = services.BuildServiceProvider();

            var client = new ChatClientBuilder(new EchoChatClient()).UseAISentinel().Build(sp);
            await client.GetResponseAsync([new ChatMessage(ChatRole.User, "hello")]);
            await Task.Delay(200);

            Assert.NotEmpty(recording.Batches);
            // Wait briefly for the NDJSON file write to flush
            await Task.Delay(200);
            // Dispose so the FileStream releases the file before reading
            await ((IAsyncDisposable)sp).DisposeAsync();
            var lines = File.ReadAllLines(ndjsonPath);
            Assert.NotEmpty(lines);
        }
        finally
        {
            try { File.Delete(ndjsonPath); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    [Fact]
    public async Task SlowForwarder_DoesNotBlockPipeline()
    {
        var slow = new SlowForwarder(TimeSpan.FromSeconds(2));
        var services = new ServiceCollection();
        services.AddAISentinel(opts => { });
        services.AddSingleton<IAuditForwarder>(slow);
        var sp = services.BuildServiceProvider();

        var client = new ChatClientBuilder(new EchoChatClient()).UseAISentinel().Build(sp);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        await client.GetResponseAsync([new ChatMessage(ChatRole.User, "hello")]);
        sw.Stop();

        Assert.True(sw.Elapsed < TimeSpan.FromMilliseconds(500), $"Pipeline should NOT block on slow forwarder; elapsed={sw.Elapsed}");
    }

    private sealed class RecordingForwarder : IAuditForwarder
    {
        public List<IReadOnlyList<AuditEntry>> Batches { get; } = new();
        public ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
        {
            lock (Batches) Batches.Add(batch);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class SlowForwarder(TimeSpan delay) : IAuditForwarder
    {
        public ValueTask SendAsync(IReadOnlyList<AuditEntry> batch, CancellationToken ct)
            => new(Task.Delay(delay, ct));
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
