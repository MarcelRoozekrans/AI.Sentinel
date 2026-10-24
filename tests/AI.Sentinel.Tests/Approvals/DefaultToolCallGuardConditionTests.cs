using System.Text.Json;
using AI.Sentinel.Approvals;
using AI.Sentinel.Authorization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using ZeroAlloc.Authorization;
using ZeroAlloc.Results;

namespace AI.Sentinel.Tests.Approvals;

public class DefaultToolCallGuardConditionTests
{
    private sealed record TestSec(string Id) : ISecurityContext
    {
        public IReadOnlySet<string> Roles { get; } = new HashSet<string>(StringComparer.Ordinal);
        public IReadOnlyDictionary<string, string> Claims { get; } = new Dictionary<string, string>(StringComparer.Ordinal);
    }

    /// <summary>Returns a fixed state and records the policy name of every request.</summary>
    private sealed class RecordingStore(ApprovalState fixedResult) : IApprovalStore
    {
        public List<string> PolicyNames { get; } = [];

        public ValueTask<ApprovalState> EnsureRequestAsync(ISecurityContext c, ApprovalSpec s, ApprovalContext ctx, CancellationToken t)
        {
            PolicyNames.Add(s.PolicyName);
            return ValueTask.FromResult(fixedResult);
        }

        public ValueTask<ApprovalState> WaitForDecisionAsync(string id, TimeSpan to, CancellationToken t) =>
            ValueTask.FromResult(fixedResult);
    }

    private sealed class DenyAll : IAuthorizationPolicy
    {
        public ValueTask<UnitResult<AuthorizationFailure>> EvaluateAsync(
            ISecurityContext ctx, CancellationToken ct = default) =>
            new(UnitResult<AuthorizationFailure>.Failure(
                new AuthorizationFailure(AuthorizationFailure.DefaultDenyCode, "deny-all says no")));
    }

    private sealed class CapturingLogger : ILogger<DefaultToolCallGuard>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));
    }

    private static readonly ApprovalState Pending =
        new ApprovalState.Pending("req-1", "https://example.test/approve/req-1", DateTimeOffset.UtcNow);

    private static readonly ApprovalState Active =
        new ApprovalState.Active(DateTimeOffset.UtcNow.AddMinutes(15));

    private static DefaultToolCallGuard BuildGuard(
        IApprovalStore store,
        ToolPolicyDefault @default = ToolPolicyDefault.Allow,
        IReadOnlyDictionary<string, IAuthorizationPolicy>? policies = null,
        ILogger<DefaultToolCallGuard>? logger = null,
        params ToolCallPolicyBinding[] bindings) =>
        new(
            bindings: bindings,
            policiesByName: policies ?? new Dictionary<string, IAuthorizationPolicy>(StringComparer.Ordinal),
            @default: @default,
            approvalStore: store,
            logger: logger ?? NullLogger<DefaultToolCallGuard>.Instance);

    private static ToolCallPolicyBinding Approval(ApprovalSpec spec) =>
        new("Bash", spec.PolicyName, spec);

    private static ApprovalSpec ProdDelete() =>
        new ApprovalSpec { PolicyName = "approval:Bash" }.WhenArgument("$.command", "delete ns prod");

    private static ApprovalSpec AnyDelete() =>
        new ApprovalSpec { PolicyName = "approval:Bash[1]" }.WhenArgument("$.command", "delete");

    private static JsonElement Args(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    private static JsonElement Command(string command) =>
        JsonSerializer.SerializeToElement(new Dictionary<string, string>(StringComparer.Ordinal) { ["command"] = command });

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task FirstMatchingEntryWins()
    {
        var store = new RecordingStore(Pending);
        var guard = BuildGuard(store, bindings: [Approval(ProdDelete()), Approval(AnyDelete())]);

        await guard.AuthorizeAsync(new TestSec("alice"), "Bash", Command("kubectl delete ns prod"), Ct);
        Assert.Equal(["approval:Bash"], store.PolicyNames);

        store.PolicyNames.Clear();
        await guard.AuthorizeAsync(new TestSec("alice"), "Bash", Command("kubectl delete pod x"), Ct);
        Assert.Equal(["approval:Bash[1]"], store.PolicyNames);
    }

    [Fact]
    public async Task NoEntryHolds_IsAllowed_UnderDenyDefault()
    {
        var store = new RecordingStore(Pending);
        var spec = new ApprovalSpec { PolicyName = "approval:Bash" }.WhenArgument("$.command", "kubectl delete");
        var guard = BuildGuard(store, ToolPolicyDefault.Deny, bindings: [Approval(spec)]);

        var d = await guard.AuthorizeAsync(new TestSec("alice"), "Bash", Command("ls"), Ct);

        Assert.IsType<AuthorizationDecision.AllowDecision>(d);
        Assert.Empty(store.PolicyNames);
    }

    [Fact]
    public async Task GroupSitsAtFirstMemberSlot()
    {
        var store = new RecordingStore(Active);
        var policies = new Dictionary<string, IAuthorizationPolicy>(StringComparer.Ordinal) { ["deny-all"] = new DenyAll() };
        var guard = BuildGuard(store, policies: policies, bindings:
        [
            Approval(ProdDelete()),
            new ToolCallPolicyBinding("Bash", "deny-all"),
            Approval(AnyDelete()),
        ]);

        var d = await guard.AuthorizeAsync(new TestSec("alice"), "Bash", Command("kubectl delete pod x"), Ct);

        var deny = Assert.IsType<AuthorizationDecision.DenyDecision>(d);
        Assert.Equal("deny-all", deny.PolicyName);
        Assert.Equal(["approval:Bash[1]"], store.PolicyNames);
    }

    [Fact]
    public async Task StringArgs_FailClosed()
    {
        var store = new RecordingStore(Pending);
        var guard = BuildGuard(store, bindings: [Approval(ProdDelete())]);

        var d = await guard.AuthorizeAsync(new TestSec("alice"), "Bash", Args("\"rm -rf /\""), Ct);

        Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(d);
        Assert.Equal(["approval:Bash"], store.PolicyNames);
    }

    [Fact]
    public async Task UndefinedArgs_FailClosed()
    {
        var store = new RecordingStore(Pending);
        var guard = BuildGuard(store, bindings: [Approval(ProdDelete())]);

        var d = await guard.AuthorizeAsync(new TestSec("alice"), "Bash", default, Ct);

        Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(d);
        Assert.Equal(["approval:Bash"], store.PolicyNames);
    }

    [Fact]
    public async Task Timeout_FailsClosed_AndWarnsOnce()
    {
        // The backreference makes NonBacktracking reject the pattern, so the 100 ms timeout applies.
        // Two timing-out conditions on one rule still give a single warning.
        var spec = new ApprovalSpec { PolicyName = "approval:Bash" }
            .WhenArgument("$.command", "^(a+)+\\1$")
            .WhenArgument("$.command", "^(a+)+\\1$");
        var store = new RecordingStore(Pending);
        var logger = new CapturingLogger();
        var guard = BuildGuard(store, logger: logger, bindings: [Approval(spec)]);

        var d = await guard.AuthorizeAsync(new TestSec("alice"), "Bash", Command(new string('a', 50_000) + "!"), Ct);

        Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(d);
        var warning = Assert.Single(logger.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains("approval:Bash", warning.Message, StringComparison.Ordinal);
        Assert.Contains("$.command", warning.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CallScope_NameCarriesFingerprint()
    {
        var spec = new ApprovalSpec { PolicyName = "approval:Bash", GrantScope = ApprovalGrantScope.Call };
        var store = new RecordingStore(Pending);
        var guard = BuildGuard(store, bindings: [Approval(spec)]);

        var d = await guard.AuthorizeAsync(new TestSec("alice"), "Bash", Command("ls"), Ct);

        var name = Assert.Single(store.PolicyNames);
        Assert.Matches("^approval:Bash#[0-9a-f]{32}$", name);
        var r = Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(d);
        Assert.Equal(name, r.PolicyName);
        Assert.Equal("approval:Bash", spec.PolicyName);
    }

    [Fact]
    public async Task CallScope_DeniedRequest_DenyCarriesFingerprint()
    {
        var spec = new ApprovalSpec { PolicyName = "approval:Bash", GrantScope = ApprovalGrantScope.Call };
        var store = new RecordingStore(new ApprovalState.Denied("no", DateTimeOffset.UtcNow));
        var guard = BuildGuard(store, bindings: [Approval(spec)]);

        var d = await guard.AuthorizeAsync(new TestSec("alice"), "Bash", Command("ls"), Ct);

        var deny = Assert.IsType<AuthorizationDecision.DenyDecision>(d);
        Assert.Equal(Assert.Single(store.PolicyNames), deny.PolicyName);
    }

    [Fact]
    public async Task CallScope_OtherArgs_OtherRequest()
    {
        var spec = new ApprovalSpec { PolicyName = "approval:Bash", GrantScope = ApprovalGrantScope.Call };
        var store = new InMemoryApprovalStore();
        var guard = BuildGuard(store, bindings: [Approval(spec)]);
        var caller = new TestSec("alice");

        var first = Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(
            await guard.AuthorizeAsync(caller, "Bash", Args("{\"command\":\"ls\",\"cwd\":\"/\"}"), Ct));
        await ((IApprovalAdmin)store).ApproveAsync(first.RequestId, "approver", note: null, Ct);

        var same = await guard.AuthorizeAsync(caller, "Bash", Args("{ \"cwd\" : \"/\", \"command\" : \"ls\" }"), Ct);
        Assert.IsType<AuthorizationDecision.AllowDecision>(same);

        var other = Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(
            await guard.AuthorizeAsync(caller, "Bash", Args("{\"command\":\"rm -rf /\",\"cwd\":\"/\"}"), Ct));
        Assert.NotEqual(first.RequestId, other.RequestId, StringComparer.Ordinal);
    }

    [Fact]
    public async Task CallScope_WildcardRule_OtherToolSameArgs_OtherRequest()
    {
        var spec = new ApprovalSpec { PolicyName = "approval:mcp__fs__*", GrantScope = ApprovalGrantScope.Call };
        var store = new InMemoryApprovalStore();
        var guard = BuildGuard(store, bindings: [new ToolCallPolicyBinding("mcp__fs__*", spec.PolicyName, spec)]);
        var caller = new TestSec("alice");
        var args = Args("{\"path\":\"/etc/prod.conf\"}");

        var read = Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(
            await guard.AuthorizeAsync(caller, "mcp__fs__read_file", args, Ct));

        // A pending request for one tool is not handed out for another tool with the same arguments.
        var deletePending = Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(
            await guard.AuthorizeAsync(caller, "mcp__fs__delete_file", args, Ct));
        Assert.NotEqual(read.RequestId, deletePending.RequestId, StringComparer.Ordinal);
        Assert.NotEqual(read.PolicyName, deletePending.PolicyName, StringComparer.Ordinal);

        await ((IApprovalAdmin)store).ApproveAsync(read.RequestId, "approver", note: null, Ct);

        Assert.IsType<AuthorizationDecision.AllowDecision>(
            await guard.AuthorizeAsync(caller, "mcp__fs__read_file", args, Ct));
        var delete = Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(
            await guard.AuthorizeAsync(caller, "mcp__fs__delete_file", args, Ct));
        Assert.Equal(deletePending.RequestId, delete.RequestId);
    }

    [Fact]
    public async Task RuleScope_GrantDoesNotCrossRules()
    {
        var store = new InMemoryApprovalStore();
        var guard = BuildGuard(store, bindings: [Approval(ProdDelete()), Approval(AnyDelete())]);
        var caller = new TestSec("alice");

        var anyDelete = Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(
            await guard.AuthorizeAsync(caller, "Bash", Command("kubectl delete pod x"), Ct));
        Assert.Equal("approval:Bash[1]", anyDelete.PolicyName);
        await ((IApprovalAdmin)store).ApproveAsync(anyDelete.RequestId, "approver", note: null, Ct);

        var prod = await guard.AuthorizeAsync(caller, "Bash", Command("kubectl delete ns prod"), Ct);

        var r = Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(prod);
        Assert.Equal("approval:Bash", r.PolicyName);
    }

    [Fact]
    public async Task BindingWithoutConditions_StringArgs_BehavesAsBefore()
    {
        var store = new RecordingStore(Active);
        var guard = BuildGuard(store, bindings: [Approval(new ApprovalSpec { PolicyName = "approval:Bash" })]);

        var d = await guard.AuthorizeAsync(new TestSec("alice"), "Bash", Args("\"ls\""), Ct);

        Assert.IsType<AuthorizationDecision.AllowDecision>(d);
        Assert.Equal(["approval:Bash"], store.PolicyNames);
    }

    [Theory]
    [InlineData("{\"command\":\"\\ud800\"}")]
    [InlineData("{\"\\ud800\":1,\"command\":\"ls\"}")]
    public async Task LoneSurrogate_WhenRule_FailsClosed(string json)
    {
        var store = new RecordingStore(Pending);
        var guard = BuildGuard(store, bindings: [Approval(ProdDelete())]);

        var d = await guard.AuthorizeAsync(new TestSec("alice"), "Bash", Args(json), Ct);

        Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(d);
        Assert.Equal(["approval:Bash"], store.PolicyNames);
    }

    [Fact]
    public async Task LoneSurrogate_CallScope_FailsClosed()
    {
        var spec = new ApprovalSpec { PolicyName = "approval:Bash", GrantScope = ApprovalGrantScope.Call };
        var store = new RecordingStore(Pending);
        var guard = BuildGuard(store, bindings: [Approval(spec)]);

        var d = await guard.AuthorizeAsync(new TestSec("alice"), "Bash", Args("{\"command\":\"\\ud800\"}"), Ct);

        var r = Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(d);
        Assert.Matches("^approval:Bash#[0-9a-f]{32}$", r.PolicyName);
    }

    [Theory]
    [InlineData("{\"command\":\"kubectl delete ns prod\",\"command\":\"ls\"}")]
    [InlineData("{\"command\":\"ls\",\"command\":\"kubectl delete ns prod\"}")]
    public async Task DuplicateKey_FailsClosed(string json)
    {
        var store = new RecordingStore(Pending);
        var logger = new CapturingLogger();
        var guard = BuildGuard(store, logger: logger, bindings: [Approval(ProdDelete())]);

        var d = await guard.AuthorizeAsync(new TestSec("alice"), "Bash", Args(json), Ct);

        Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(d);
        Assert.Equal(["approval:Bash"], store.PolicyNames);
        var warning = Assert.Single(logger.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains("$.command", warning.Message, StringComparison.Ordinal);
    }
}
