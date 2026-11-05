using System.Runtime.CompilerServices;
using AI.Sentinel.Audit;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Intervention;
using AI.Sentinel.Mcp;
using AI.Sentinel.Redaction;
using Microsoft.Extensions.AI;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Xunit;

namespace AI.Sentinel.Tests.Mcp;

// #544. Shared by the MCP fail-closed tests: a pipeline whose detection stage throws.
internal static class McpFailClosedFixture
{
    internal const string LeakMarker = "leak-4111111111111111";

    internal sealed class ThrowingDetectionPipeline(
        Func<Exception>? exception = null, int throwFromCall = 1, IDetectionPipeline? inner = null) : IDetectionPipeline
    {
        private readonly Func<Exception> _exception = exception ?? (() => new InvalidOperationException(LeakMarker));
        private readonly IDetectionPipeline _inner = inner
            ?? new DetectionPipeline([], configurations: null, reviewer: null, redactByDefault: true);
        private int _calls;

        public IReadOnlyList<IRedactingDetector> Redactors => _inner.Redactors;

        public ValueTask<PipelineResult> RunAsync(SentinelContext ctx, CancellationToken ct)
        {
            var call = Interlocked.Increment(ref _calls);
            if (call >= throwFromCall)
            {
                return ValueTask.FromException<PipelineResult>(_exception());
            }

            return _inner.RunAsync(ctx, ct);
        }
    }

    private sealed class NullClient : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public object? GetService(Type serviceType, object? serviceKey = null) => null;

        public void Dispose() { }
    }

    internal static SentinelPipeline ThrowingPipeline(
        Func<Exception>? exception = null, int throwFromCall = 1, IDetectionPipeline? inner = null, IAuditStore? auditStore = null)
    {
        var opts = new SentinelOptions();
        return new SentinelPipeline(
            new NullClient(),
            new ThrowingDetectionPipeline(exception, throwFromCall, inner),
            auditStore ?? new RingBufferAuditStore(100),
            new InterventionEngine(opts, null),
            opts);
    }

    internal static RequestContext<T> Context<T>(T parameters)
    {
        var ctx = (RequestContext<T>)RuntimeHelpers.GetUninitializedObject(typeof(RequestContext<T>));
        ctx.Params = parameters;
        return ctx;
    }

    internal static PlaceholderStore NewStore() => new(PlaceholderStore.DefaultIdleExpiry);

    internal static void AssertFailClosed(McpProtocolException ex, string expectedType = "InvalidOperationException")
    {
        Assert.Equal(McpErrorCode.InternalError, ex.ErrorCode);
        Assert.Contains($"Blocked by AI.Sentinel: internal error ({expectedType})", ex.Message);
        Assert.DoesNotContain(LeakMarker, ex.Message);
    }
}
