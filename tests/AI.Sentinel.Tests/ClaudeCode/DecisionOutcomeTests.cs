using AI.Sentinel.Audit;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Detection;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode;

public class DecisionOutcomeTests
{
    private static OutcomeDecision D(DecisionOutcome outcome, string reason, params string[] sources) =>
        new(outcome, reason, sources);

    [Fact]
    public void Outcomes_AreOrderedStrictestFirst()
    {
        DecisionOutcome[] expected =
            [DecisionOutcome.Deny, DecisionOutcome.Ask, DecisionOutcome.Guidance, DecisionOutcome.Allow, DecisionOutcome.Defer];
        Assert.Equal(expected, Enum.GetValues<DecisionOutcome>().OrderBy(o => (int)o));
    }

    [Theory]
    [InlineData("Deny", "Defer", "Deny")]
    [InlineData("Defer", "Ask", "Ask")]
    [InlineData("Guidance", "Allow", "Guidance")]
    [InlineData("Allow", "Defer", "Allow")]
    [InlineData("Ask", "Guidance", "Ask")]
    [InlineData("Ask", "Deny", "Deny")]
    public void Strictest_PicksTheStricterOutcome_InEitherOrder(string first, string second, string strictest)
    {
        var a = Enum.Parse<DecisionOutcome>(first);
        var b = Enum.Parse<DecisionOutcome>(second);
        var expected = Enum.Parse<DecisionOutcome>(strictest);
        Assert.Equal(expected, DecisionOutcomes.Strictest(a, b));
        Assert.Equal(expected, DecisionOutcomes.Strictest(b, a));
    }

    [Fact]
    public void Strictest_OfDecisions_KeepsTheStrictestReasonAndSourcesOnly()
    {
        var result = OutcomeDecision.Strictest(
        [
            D(DecisionOutcome.Guidance, "careful", "bundle-a"),
            D(DecisionOutcome.Deny, "no", "SENTINEL_HOOK_ON_HIGH"),
            D(DecisionOutcome.Defer, "", "local"),
        ]);

        Assert.Equal(DecisionOutcome.Deny, result.Outcome);
        Assert.Equal("no", result.Reason);
        Assert.Equal(["SENTINEL_HOOK_ON_HIGH"], result.Sources);
    }

    [Fact]
    public void Strictest_OfDecisionsWithTheSameOutcome_JoinsSourcesWithoutRepeats()
    {
        var result = OutcomeDecision.Strictest(
        [
            D(DecisionOutcome.Ask, "check one", "a", "b"),
            D(DecisionOutcome.Ask, "check two", "b", "c"),
        ]);

        Assert.Equal(["a", "b", "c"], result.Sources);
        Assert.Equal("check one; check two", result.Reason);
    }

    [Fact]
    public void Strictest_OfNoDecisions_Throws() =>
        Assert.Throws<ArgumentException>(() => OutcomeDecision.Strictest([]));

    [Theory]
    [InlineData(HookDecision.Block, "Deny")]
    [InlineData(HookDecision.Warn, "Guidance")]
    [InlineData(HookDecision.Allow, "Defer")]
    public void SeverityActions_MapToOutcomes_AndBack(HookDecision action, string expected)
    {
        var outcome = Enum.Parse<DecisionOutcome>(expected);
        Assert.Equal(outcome, DecisionOutcomes.FromHook(action));
        Assert.Equal(action, DecisionOutcomes.ToHook(outcome));
    }

    [Fact]
    public void Decision_CarriesReasonSourcesPolicyVersionAndPlace()
    {
        var d = new OutcomeDecision(DecisionOutcome.Deny, "blocked", ["bundle-a"], "v7", "resident");

        Assert.Equal("blocked", d.Reason);
        Assert.Equal(["bundle-a"], d.Sources);
        Assert.Equal("v7", d.PolicyVersion);
        Assert.Equal("resident", d.DecidedAt);
    }

    [Fact]
    public void Decision_PolicyVersionIsEmptyAndPlaceIsInProcess_ByDefault()
    {
        var d = OutcomeDecision.FromHook(HookDecision.Block, "r", "SENTINEL_HOOK_ON_HIGH");

        Assert.Equal(string.Empty, d.PolicyVersion);
        Assert.Equal(OutcomeDecision.InProcess, d.DecidedAt);
    }

    [Fact]
    public async Task Audit_RecordsReasonSourcesPolicyVersionAndPlace()
    {
        var store = new RingBufferAuditStore();
        var output = new OutcomeDecision(DecisionOutcome.Ask, "needs a look", ["bundle-a", "local"], "v7", "resident").ToHookOutput(canAsk: true);

        await OutcomeAudit.RecordAsync(store, [], output, "s-1", CancellationToken.None);

        var entries = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(), CancellationToken.None)) entries.Add(e);
        var entry = Assert.Single(entries);
        Assert.Equal(Severity.None, entry.Severity);
        Assert.Equal(OutcomeAudit.PolicyCode, entry.PolicyCode);
        Assert.Equal("s-1", entry.SessionId);
        Assert.Equal("ask: needs a look; sources=bundle-a,local; policy=v7; decided=resident", entry.Summary);
    }

    [Fact]
    public async Task Audit_WritesNothing_ForADecisionWithoutAnOutcome()
    {
        var store = new RingBufferAuditStore();

        await OutcomeAudit.RecordAsync(store, [], new HookOutput { Decision = HookDecision.Warn, Reason = "x" }, "s-1", CancellationToken.None);

        var entries = new List<AuditEntry>();
        await foreach (var e in store.QueryAsync(new AuditQuery(), CancellationToken.None)) entries.Add(e);
        Assert.Empty(entries);
    }
}
