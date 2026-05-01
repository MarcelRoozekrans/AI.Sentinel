using AI.Sentinel.Approvals;
using AI.Sentinel.Authorization;
using Microsoft.Extensions.AI;
using Xunit;
using ZeroAlloc.Authorization;

namespace AI.Sentinel.Tests.Authorization;

public class AuthorizationChatClientApprovalTests
{
    private sealed record TestSec(string Id) : ISecurityContext
    {
#pragma warning disable HLQ001 // Boxing on init is fine for a test helper
        public IReadOnlySet<string> Roles { get; } = new HashSet<string>(StringComparer.Ordinal);
        public IReadOnlyDictionary<string, string> Claims { get; } = new Dictionary<string, string>(StringComparer.Ordinal);
#pragma warning restore HLQ001
    }

    private sealed class StubGuard(AuthorizationDecision[] sequence) : IToolCallGuard
    {
        private int _i;
        public ValueTask<AuthorizationDecision> AuthorizeAsync(
            ISecurityContext c, string toolName, System.Text.Json.JsonElement args, CancellationToken ct = default) =>
            ValueTask.FromResult(sequence[Math.Min(_i++, sequence.Length - 1)]);
    }

    private sealed class FakeInner : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> m, ChatOptions? o = null, CancellationToken c = default) =>
            Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, "ok")));
        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> m, ChatOptions? o = null, CancellationToken c = default) =>
            throw new NotSupportedException();
        public object? GetService(Type t, object? key = null) => null;
        public void Dispose() { }
    }

    private static IEnumerable<ChatMessage> MessagesWithToolCall() =>
    [
        new ChatMessage(ChatRole.Assistant, [new FunctionCallContent("call-1", "delete_database", new Dictionary<string, object?>(StringComparer.Ordinal) { ["table"] = "users" })])
    ];

    [Fact]
    public async Task RequireApproval_StoreActivatesDuringWait_AllowsCall()
    {
        var store = new InMemoryApprovalStore();
        var caller = new TestSec("alice");
        var spec = new ApprovalSpec { PolicyName = "approval:delete_database", WaitTimeout = TimeSpan.FromSeconds(2) };

        // Seed a pending request so WaitForDecisionAsync has something to wait on.
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(caller, spec,
            new ApprovalContext("delete_database", default, null), default);

        // Guard returns RequireApproval first; on re-query (after wait → Active) returns Allow,
        // matching DefaultToolCallGuard's real behaviour where EvaluateApprovalAsync returns null
        // (skip binding) when the approval is Active and the remaining bindings allow.
        var guard = new StubGuard([
            AuthorizationDecision.RequireApproval("approval:delete_database", pending.RequestId, pending.ApprovalUrl, pending.RequestedAt, TimeSpan.FromSeconds(2)),
            AuthorizationDecision.Allow,
        ]);

        var client = new AuthorizationChatClient(new FakeInner(), guard, () => caller, audit: null, approvalStore: store);

        // Approve in the background after a short delay
        _ = Task.Run(async () => { await Task.Delay(100); await store.ApproveAsync(pending.RequestId, "boss", null, default); });

        var response = await client.GetResponseAsync(MessagesWithToolCall());
        Assert.NotNull(response);   // call proceeded — approval landed in time
    }

    [Fact]
    public async Task RequireApproval_TimesOut_ThrowsAuthorizationException()
    {
        var store = new InMemoryApprovalStore();
        var caller = new TestSec("alice");
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(caller,
            new ApprovalSpec { PolicyName = "approval:delete_database" },
            new ApprovalContext("delete_database", default, null), default);

        var guard = new StubGuard([
            AuthorizationDecision.RequireApproval("approval:delete_database", pending.RequestId, pending.ApprovalUrl, pending.RequestedAt, TimeSpan.FromMilliseconds(50)),
        ]);

        var client = new AuthorizationChatClient(new FakeInner(), guard, () => caller, audit: null, approvalStore: store);

        var ex = await Assert.ThrowsAsync<ToolCallAuthorizationException>(() => client.GetResponseAsync(MessagesWithToolCall()));
        Assert.Contains("timed out", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RequireApproval_StoreDenies_ThrowsAuthorizationException()
    {
        var store = new InMemoryApprovalStore();
        var caller = new TestSec("alice");
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(caller,
            new ApprovalSpec { PolicyName = "approval:delete_database" },
            new ApprovalContext("delete_database", default, null), default);

        var guard = new StubGuard([
            AuthorizationDecision.RequireApproval("approval:delete_database", pending.RequestId, pending.ApprovalUrl, pending.RequestedAt, TimeSpan.FromSeconds(2)),
        ]);

        var client = new AuthorizationChatClient(new FakeInner(), guard, () => caller, audit: null, approvalStore: store);

        _ = Task.Run(async () => { await Task.Delay(50); await store.DenyAsync(pending.RequestId, "boss", "no", default); });

        var ex = await Assert.ThrowsAsync<ToolCallAuthorizationException>(() => client.GetResponseAsync(MessagesWithToolCall()));
        Assert.Contains("denied", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RequireApproval_StackedDenyingPolicy_DeniesAfterWait()
    {
        // Setup: guard returns RequireApproval first, then on re-query (after wait → Active)
        // returns Deny because a stacked RequireToolPolicy binding rejects.
        var store = new InMemoryApprovalStore();
        var caller = new TestSec("alice");
        var pending = (ApprovalState.Pending)await store.EnsureRequestAsync(caller,
            new ApprovalSpec { PolicyName = "approval:delete_database" },
            new ApprovalContext("delete_database", default, null), default);

        var guard = new StubGuard([
            AuthorizationDecision.RequireApproval(
                "approval:delete_database", pending.RequestId, pending.ApprovalUrl,
                pending.RequestedAt, TimeSpan.FromSeconds(2)),
            AuthorizationDecision.Deny("StackedPolicy", "stacked policy denied"),
        ]);

        var client = new AuthorizationChatClient(new FakeInner(), guard, () => caller, audit: null, approvalStore: store);

        // Approve in background — guard's first response is RequireApproval; client waits;
        // store flips to Active; client re-queries; guard returns the second sequence entry (Deny).
        _ = Task.Run(async () => { await Task.Delay(50); await store.ApproveAsync(pending.RequestId, "boss", null, default); });

        var ex = await Assert.ThrowsAsync<ToolCallAuthorizationException>(
            () => client.GetResponseAsync(MessagesWithToolCall()));
        Assert.Contains("stacked policy denied", ex.Message, StringComparison.Ordinal);
    }
}
