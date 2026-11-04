using System.Text.Json;
using AI.Sentinel.Approvals;
using AI.Sentinel.Approvals.Conditions;
using AI.Sentinel.Approvals.EntraPim;
using AI.Sentinel.Approvals.Semantic;
using AI.Sentinel.Authorization;
using AI.Sentinel.Detection;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;
using ZeroAlloc.Authorization;
using ZeroAlloc.Results;

namespace AI.Sentinel.Tests.Approvals.Semantic;

/// <summary>The semantic approval stage of the tool-call guard, and how DI builds it.</summary>
public class DefaultToolCallGuardSemanticTests
{
    private const string Destructive = "rm -rf /";
    private const string OtherDestructive = "DROP TABLE users;";
    private const string Benign = "ls -la";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static readonly TestSecurityContext Caller = new("alice");

    private static JsonElement Command(string command) =>
        JsonSerializer.SerializeToElement(new Dictionary<string, string>(StringComparer.Ordinal) { ["command"] = command });

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));
    }

    /// <summary>Returns a fixed state and records every request.</summary>
    private sealed class FixedStore(ApprovalState state) : IApprovalStore
    {
        public List<(ApprovalSpec Spec, ApprovalContext Context)> Requests { get; } = [];

        public ValueTask<ApprovalState> EnsureRequestAsync(ISecurityContext c, ApprovalSpec s, ApprovalContext ctx, CancellationToken t)
        {
            Requests.Add((s, ctx));
            return ValueTask.FromResult(state);
        }

        public ValueTask<ApprovalState> WaitForDecisionAsync(string id, TimeSpan to, CancellationToken t) =>
            ValueTask.FromResult(state);
    }

    private sealed class ThrowingEmbeddingGenerator(Func<Exception> exception) : IEmbeddingGenerator<string, Embedding<float>>
    {
        public Task<GeneratedEmbeddings<Embedding<float>>> GenerateAsync(
            IEnumerable<string> values, EmbeddingGenerationOptions? options = null, CancellationToken cancellationToken = default) =>
            throw exception();

        public object? GetService(Type serviceType, object? serviceKey = null) => null;
        public void Dispose() { }
    }

    private sealed class AllowAll : IAuthorizationPolicy
    {
        public ValueTask<UnitResult<AuthorizationFailure>> EvaluateAsync(ISecurityContext ctx, CancellationToken ct = default) =>
            new(UnitResult<AuthorizationFailure>.Success());
    }

    private static readonly ApprovalState Pending =
        new ApprovalState.Pending("req-1", "https://example.test/approve/req-1", DateTimeOffset.UtcNow);

    private static readonly ApprovalState Active = new ApprovalState.Active(DateTimeOffset.UtcNow.AddMinutes(15));

    private static SemanticApprovalSpec OperatorSpec() => new()
    {
        BackendBinding = "Operator",
        GrantDuration = TimeSpan.FromMinutes(7),
        RequireJustification = false,
        WaitTimeout = TimeSpan.FromSeconds(42),
    };

    private static SemanticApprovalMatcher Matcher(
        IEmbeddingGenerator<string, Embedding<float>> generator, SemanticApprovalSpec? spec = null, string pattern = "Bash") =>
        new(new EmbeddingScope(generator, new InMemoryLruEmbeddingCache(), null),
            new SemanticApprovalSettings(),
            [(pattern, spec ?? OperatorSpec())],
            maxBytes: 1024);

    private static DefaultToolCallGuard Guard(
        IApprovalStore store,
        SemanticApprovalMatcher? semantic,
        ToolPolicyDefault @default = ToolPolicyDefault.Allow,
        ILogger<DefaultToolCallGuard>? logger = null,
        params ToolCallPolicyBinding[] bindings) =>
        new(bindings,
            new Dictionary<string, IAuthorizationPolicy>(StringComparer.Ordinal) { ["allow-all"] = new AllowAll() },
            @default,
            store,
            logger,
            semantic);

    private static ToolCallPolicyBinding Rule(ApprovalSpec spec, string pattern = "Bash") => new(pattern, spec.PolicyName, spec);

    [Fact]
    public async Task UncoveredTool_NoEmbeddingRequest()
    {
        var recording = new RecordingEmbeddingGenerator(new ExactMatchEmbeddingGenerator());
        var store = new FixedStore(Pending);
        var guard = Guard(store, Matcher(recording));

        var d = await guard.AuthorizeAsync(Caller, "Read", Command(Destructive), Ct);

        Assert.IsType<AuthorizationDecision.AllowDecision>(d);
        Assert.Equal(0, recording.Calls);
        Assert.Empty(store.Requests);
    }

    [Fact]
    public async Task RuleRequiresApproval_SemanticSkipped()
    {
        var recording = new RecordingEmbeddingGenerator(new ExactMatchEmbeddingGenerator());
        var store = new FixedStore(Pending);
        var guard = Guard(store, Matcher(recording), bindings: Rule(new ApprovalSpec { PolicyName = "approval:Bash" }));

        var d = await guard.AuthorizeAsync(Caller, "Bash", Command(Destructive), Ct);

        Assert.Equal("approval:Bash", Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(d).PolicyName);
        Assert.Equal(0, recording.Calls);
        Assert.Single(store.Requests);
    }

    [Fact]
    public async Task RuleGrantActive_SemanticSkipped()
    {
        var recording = new RecordingEmbeddingGenerator(new ExactMatchEmbeddingGenerator());
        var store = new FixedStore(Active);
        // The second group selects nothing for these arguments; the first group's active grant still suppresses the matcher.
        var guard = Guard(store, Matcher(recording), bindings:
        [
            Rule(new ApprovalSpec { PolicyName = "approval:Bash" }),
            Rule(new ApprovalSpec { PolicyName = "approval:B*" }.WhenArgument("$.command", "kubectl"), "B*"),
        ]);

        var d = await guard.AuthorizeAsync(Caller, "Bash", Command(Destructive), Ct);

        Assert.IsType<AuthorizationDecision.AllowDecision>(d);
        Assert.Equal(0, recording.Calls);
        Assert.Equal(["approval:Bash"], store.Requests.Select(r => r.Spec.PolicyName), StringComparer.Ordinal);
    }

    [Fact]
    public async Task NoRuleMatched_Flagged_RequiresApproval_WithSemanticPolicyNameAndReason()
    {
        var store = new FixedStore(Pending);
        var guard = Guard(store, Matcher(new ExactMatchEmbeddingGenerator()), bindings:
            Rule(new ApprovalSpec { PolicyName = "approval:Bash" }.WhenArgument("$.command", "kubectl")));
        var args = Command(Destructive);

        var d = await guard.AuthorizeAsync(Caller, "Bash", args, Ct);

        var expectedName = $"semantic:Bash#{ArgumentFingerprint.Compute("Bash", args)}";
        var expectedReason = "Semantic match 1.00 ≥ 0.80 on $.command: \"rm -rf /\"";
        var approval = Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(d);
        Assert.Equal(expectedName, approval.PolicyName);
        Assert.Equal(expectedReason, approval.Reason);
        Assert.Equal(TimeSpan.FromSeconds(42), approval.WaitTimeout);

        var (spec, context) = Assert.Single(store.Requests);
        Assert.Equal(expectedName, spec.PolicyName);
        Assert.Equal(ApprovalGrantScope.Call, spec.GrantScope);
        Assert.Equal("Operator", spec.BackendBinding);
        Assert.Equal(TimeSpan.FromMinutes(7), spec.GrantDuration);
        Assert.False(spec.RequireJustification);
        Assert.Equal(TimeSpan.FromSeconds(42), spec.WaitTimeout);
        Assert.Equal(expectedReason, context.Reason);
    }

    [Fact]
    public async Task UngovernedCoveredTool_UnderAllow_Flagged()
    {
        var store = new FixedStore(Pending);
        var guard = Guard(store, Matcher(new ExactMatchEmbeddingGenerator()));

        var d = await guard.AuthorizeAsync(Caller, "Bash", Command(Destructive), Ct);

        Assert.StartsWith("semantic:Bash#", Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(d).PolicyName, StringComparison.Ordinal);
        Assert.True(guard.CanRefuse);
    }

    [Fact]
    public async Task UngovernedCoveredTool_UnderDeny_DeniedWithoutEmbedding()
    {
        var recording = new RecordingEmbeddingGenerator(new ExactMatchEmbeddingGenerator());
        var store = new FixedStore(Pending);
        var guard = Guard(store, Matcher(recording), ToolPolicyDefault.Deny);

        var d = await guard.AuthorizeAsync(Caller, "Bash", Command(Benign), Ct);

        Assert.Equal("default", Assert.IsType<AuthorizationDecision.DenyDecision>(d).PolicyName);
        Assert.Equal(0, recording.Calls);
        Assert.Empty(store.Requests);
    }

    [Fact]
    public async Task PassingToolPolicy_SemanticStillRuns()
    {
        var store = new FixedStore(Pending);
        var guard = Guard(store, Matcher(new ExactMatchEmbeddingGenerator()), bindings: new ToolCallPolicyBinding("Bash", "allow-all"));

        var flagged = await guard.AuthorizeAsync(Caller, "Bash", Command(Destructive), Ct);
        var benign = await guard.AuthorizeAsync(Caller, "Bash", Command(Benign), Ct);

        Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(flagged);
        Assert.IsType<AuthorizationDecision.AllowDecision>(benign);
    }

    [Fact]
    public async Task EmbeddingFails_RequiresApproval_WithFailureReason()
    {
        var logger = new CapturingLogger<DefaultToolCallGuard>();
        var store = new FixedStore(Pending);
        var guard = Guard(store, Matcher(new ThrowingEmbeddingGenerator(() => new HttpRequestException("provider down"))), logger: logger);
        var args = Command(Destructive);

        var d = await guard.AuthorizeAsync(Caller, "Bash", args, Ct);

        var approval = Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(d);
        Assert.Equal($"semantic:Bash#{ArgumentFingerprint.Compute("Bash", args)}", approval.PolicyName);
        Assert.Equal("Semantic check failed: HttpRequestException; approval required (fail closed)", approval.Reason);
        var warning = Assert.Single(logger.Entries, e => e.Level == LogLevel.Warning);
        Assert.Contains("'Bash'", warning.Message, StringComparison.Ordinal);
        Assert.Contains("HttpRequestException", warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(Destructive, warning.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CallerCancelled_Propagates()
    {
        using var cts = new CancellationTokenSource();
        var generator = new ThrowingEmbeddingGenerator(() =>
        {
            cts.Cancel();
            return new HttpRequestException("aborted");
        });
        var store = new FixedStore(Pending);
        var guard = Guard(store, Matcher(generator));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => guard.AuthorizeAsync(Caller, "Bash", Command(Destructive), cts.Token).AsTask());
        Assert.Empty(store.Requests);
    }

    [Fact]
    public async Task ApprovedSemanticGrant_SameArgsAllowed_DifferentArgsAskAgain()
    {
        var store = new InMemoryApprovalStore();
        var guard = Guard(store, Matcher(new ExactMatchEmbeddingGenerator()));

        var first = await guard.AuthorizeAsync(Caller, "Bash", Command(Destructive), Ct);
        var requestId = Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(first).RequestId;
        await store.ApproveAsync(requestId, "approver", null, Ct);

        var same = await guard.AuthorizeAsync(Caller, "Bash", Command(Destructive), Ct);
        var different = await guard.AuthorizeAsync(Caller, "Bash", Command(OtherDestructive), Ct);

        Assert.IsType<AuthorizationDecision.AllowDecision>(same);
        var again = Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(different);
        Assert.NotEqual(requestId, again.RequestId, StringComparer.Ordinal);
    }

    [Fact]
    public void NoGenerator_Inert_LogsWarningOnce()
    {
        var logger = new CapturingLogger<SentinelPipeline>();
        var services = new ServiceCollection();
        services.AddAISentinel(o => o.RequireSemanticApproval("Bash", s => s.BackendBinding = "Operator"));
        services.AddSingleton<ILogger<SentinelPipeline>>(logger);
        using var sp = services.BuildServiceProvider();

        var guard = Assert.IsType<DefaultToolCallGuard>(sp.GetRequiredService<IToolCallGuard>());
        _ = sp.GetRequiredService<IToolCallGuard>();

        Assert.False(guard.CanRefuse);
        Assert.Single(logger.Entries, e => e.Level == LogLevel.Warning &&
            string.Equals(e.Message, "Semantic approvals are configured but no embedding generator is; the semantic layer is inert.", StringComparison.Ordinal));
    }

    [Fact]
    public async Task WithGenerator_DiGuardRunsSemanticStage()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(o =>
        {
            o.EmbeddingGenerator = new ExactMatchEmbeddingGenerator();
            o.RequireSemanticApproval("Bash", s => s.BackendBinding = "Operator");
        });
        await using var sp = services.BuildServiceProvider();

        var guard = sp.GetRequiredService<IToolCallGuard>();
        var d = await guard.AuthorizeAsync(Caller, "Bash", Command(Destructive), Ct);

        Assert.StartsWith("semantic:Bash#", Assert.IsType<AuthorizationDecision.RequireApprovalDecision>(d).PolicyName, StringComparison.Ordinal);
    }

    [Fact]
    public void EntraPimStore_WithSemanticTools_Throws()
    {
        var services = new ServiceCollection();
        services.AddSentinelEntraPimApprovalStore(o => o.TenantId = "tenant");
        services.AddAISentinel(o =>
        {
            o.EmbeddingGenerator = new ExactMatchEmbeddingGenerator();
            o.RequireSemanticApproval("Bash", s => s.BackendBinding = "Operator");
        });
        using var sp = services.BuildServiceProvider();

        var ex = Assert.Throws<InvalidOperationException>(() => sp.GetRequiredService<IToolCallGuard>());
        Assert.Contains("'Bash'", ex.Message, StringComparison.Ordinal);
        Assert.Contains("Entra PIM", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ReplaceExamplesWithoutExamples_Throws()
    {
        var services = new ServiceCollection();
        services.AddAISentinel(o =>
        {
            o.EmbeddingGenerator = new ExactMatchEmbeddingGenerator();
            o.RequireSemanticApproval("Bash", s => s.BackendBinding = "Operator");
            o.ConfigureSemanticApprovals(s => s.ReplaceExamples = true);
        });
        using var sp = services.BuildServiceProvider();

        var ex = Assert.Throws<InvalidOperationException>(() => sp.GetRequiredService<IToolCallGuard>());
        Assert.Contains("ReplaceExamples", ex.Message, StringComparison.Ordinal);
    }
}
