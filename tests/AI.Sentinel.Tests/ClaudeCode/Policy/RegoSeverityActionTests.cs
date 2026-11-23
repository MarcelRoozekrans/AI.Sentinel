using AI.Sentinel.ClaudeCode;
using AI.Sentinel.ClaudeCode.Policy;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Profiles;
using AI.Sentinel.Tests.Profiles;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Policy;

/// <summary>A Rego policy sets the outcome per finding severity (#655), combined with the <c>SENTINEL_HOOK_ON_*</c> variables
/// strictest-wins; a variable that is not set does not count, and a profile's severity defaults are read the same way.</summary>
[Collection("NonParallel")]
public class RegoSeverityActionTests : IDisposable
{
    private readonly List<string> _folders = [];

    public void Dispose()
    {
        foreach (var folder in _folders)
        {
            RegoPolicyTestSupport.Delete(folder);
        }

        GC.SuppressFinalize(this);
    }

    private SeverityActions Severities(string rego) => SeveritiesOf(("p/severity.rego", rego));

    private SeverityActions SeveritiesOf(params (string Path, string Rego)[] bundles)
    {
        var folder = RegoPolicyTestSupport.Folder(bundles.Select(b => (b.Path, "package sentinel\nimport rego.v1\n" + b.Rego)).ToArray());
        _folders.Add(folder);
        using var policy = LocalPolicy.Load(
            folder, RegoPolicyTestSupport.Env(), "/work/repo", RegoPolicyTestSupport.Compilers(new ChildProcessCompiler()));
        return policy.Severities();
    }

    private static HookConfig Config(SeverityActions policy, params (string Key, string Value)[] variables)
    {
        var env = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var (key, value) in variables)
        {
            env[key] = value;
        }

        return HookConfig.FromEnvironment(env) with { SeverityOutcomes = policy };
    }

    private static HookOutput Decide(HookConfig config, Severity severity, SentinelAction action = SentinelAction.Quarantine) =>
        HookPipelineRunner.Decide([new ScanFinding(DetectionResult.WithSeverity(new DetectorId("SEC-01"), severity, "found"), action)], config);

    [Fact]
    public void A_policy_that_sets_guidance_for_high_gives_guidance_when_the_variable_is_not_set()
    {
        var config = Config(Severities("severity_actions contains {\"severity\": \"high\", \"outcome\": \"guidance\"}\n"));

        var output = Decide(config, Severity.High);

        Assert.Equal(HookDecision.Warn, output.Decision);
        Assert.Equal("SEC-01 High: found", output.Reason);
    }

    [Theory]
    [InlineData("deny", "SENTINEL_HOOK_ON_HIGH", "Allow", "deny")]
    [InlineData("guidance", "SENTINEL_HOOK_ON_HIGH", "Block", "deny")]
    [InlineData("allow", "SENTINEL_HOOK_ON_HIGH", "Block", "deny")]
    [InlineData("ask", "SENTINEL_HOOK_ON_HIGH", "Warn", "ask")]
    [InlineData("guidance", "SENTINEL_HOOK_ON_HIGH", "Warn", "guidance")]
    [InlineData("guidance", "SENTINEL_HOOK_ON_HIGH", "Allow", "guidance")]
    public void When_the_policy_and_a_variable_both_set_a_severity_the_stricter_applies(
        string policyAction, string variable, string value, string expected)
    {
        var config = Config(Severities($"severity_actions contains {{\"severity\": \"high\", \"outcome\": \"{policyAction}\"}}\n"), (variable, value));

        var output = Decide(config, Severity.High);

        Assert.Equal(expected, DecisionOutcomes.Name(OutcomeOf(output)));
    }

    [Fact]
    public void A_severity_the_policy_does_not_set_keeps_the_variable_or_the_built_in_default()
    {
        var config = Config(Severities("severity_actions contains {\"severity\": \"high\", \"outcome\": \"guidance\"}\n"), ("SENTINEL_HOOK_ON_MEDIUM", "Block"));

        Assert.Equal(DecisionOutcome.Deny, OutcomeOf(Decide(config, Severity.Critical)));
        Assert.Equal(DecisionOutcome.Deny, OutcomeOf(Decide(config, Severity.Medium)));
        Assert.Equal(DecisionOutcome.Defer, OutcomeOf(Decide(config, Severity.Low)));
    }

    [Fact]
    public void A_policy_that_sets_nothing_changes_nothing()
    {
        var config = Config(Severities("deny contains \"x\" if false\n"));

        Assert.Equal(DecisionOutcome.Deny, OutcomeOf(Decide(config, Severity.High)));
        Assert.Equal(DecisionOutcome.Guidance, OutcomeOf(Decide(config, Severity.Medium)));
        Assert.Null(Decide(config, Severity.High).Outcome);
    }

    [Fact]
    public void A_severity_set_to_ask_asks_and_one_set_to_allow_approves_with_the_outcome_on_the_output()
    {
        var config = Config(Severities("severity_actions contains {\"severity\": \"medium\", \"outcome\": \"ask\"}\nseverity_actions contains {\"severity\": \"low\", \"outcome\": \"allow\"}\n"));

        var ask = Decide(config, Severity.Medium);
        var allow = Decide(config, Severity.Low);

        Assert.Equal(DecisionOutcome.Ask, ask.Outcome!.Outcome);
        Assert.Equal(DecisionOutcome.Allow, allow.Outcome!.Outcome);
        Assert.Equal(HookDecision.Allow, allow.Decision);
    }

    [Fact]
    public void An_alert_finding_is_at_most_guidance_whatever_the_policy_sets()
    {
        var config = Config(Severities("severity_actions contains {\"severity\": \"high\", \"outcome\": \"deny\"}\n"));

        Assert.Equal(DecisionOutcome.Guidance, OutcomeOf(Decide(config, Severity.High, SentinelAction.Alert)));
    }

    [Fact]
    public void Two_bundles_that_set_one_severity_to_different_outcomes_give_the_strictest()
    {
        var set = SeveritiesOf(
            ("org/severity.rego", "severity_actions contains {\"severity\": \"high\", \"outcome\": \"guidance\"}\n"),
            ("team/severity.rego", "severity_actions contains {\"severity\": \"high\", \"outcome\": \"deny\"}\nseverity_actions contains {\"severity\": \"low\", \"outcome\": \"ask\"}\n"));

        Assert.True(set.TryGet(Severity.High, out var high));
        Assert.True(set.TryGet(Severity.Low, out var low));
        Assert.Equal(DecisionOutcome.Deny, high);
        Assert.Equal(DecisionOutcome.Ask, low);
    }

    [Fact]
    public void A_policy_that_names_a_severity_or_an_outcome_that_does_not_exist_is_refused()
    {
        var severity = Assert.Throws<FormatException>(() => Severities("severity_actions contains {\"severity\": \"severe\", \"outcome\": \"deny\"}\n"));
        var action = Assert.Throws<FormatException>(() => Severities("severity_actions contains {\"severity\": \"high\", \"outcome\": \"stop\"}\n"));

        Assert.Contains("severe", severity.Message, StringComparison.Ordinal);
        Assert.Contains("stop", action.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Profile_severity_defaults_are_read_like_the_severity_actions_of_a_policy()
    {
        var fromProfile = SeverityActions.FromProfile(SignedProfileTests.Sample());

        Assert.True(fromProfile.TryGet(Severity.Critical, out var critical));
        Assert.True(fromProfile.TryGet(Severity.High, out var high));
        Assert.True(fromProfile.TryGet(Severity.Medium, out var medium));
        Assert.False(fromProfile.TryGet(Severity.Low, out _));
        Assert.Equal(DecisionOutcome.Deny, critical);
        Assert.Equal(DecisionOutcome.Deny, high);
        Assert.Equal(DecisionOutcome.Guidance, medium);

        var config = Config(fromProfile);
        Assert.Equal(DecisionOutcome.Guidance, OutcomeOf(Decide(config, Severity.Medium)));
    }

    [Fact]
    public void A_profile_and_a_policy_combine_strictest_wins()
    {
        var profile = SeverityActions.Parse(new Dictionary<string, string>(StringComparer.Ordinal) { ["high"] = "block", ["medium"] = "alert" });
        var policy = Severities("severity_actions contains {\"severity\": \"high\", \"outcome\": \"guidance\"}\nseverity_actions contains {\"severity\": \"medium\", \"outcome\": \"ask\"}\nseverity_actions contains {\"severity\": \"low\", \"outcome\": \"guidance\"}\n");

        var both = SeverityActions.Strictest(profile, policy);

        Assert.True(both.TryGet(Severity.High, out var high));
        Assert.True(both.TryGet(Severity.Medium, out var medium));
        Assert.True(both.TryGet(Severity.Low, out var low));
        Assert.Equal(DecisionOutcome.Deny, high);
        Assert.Equal(DecisionOutcome.Ask, medium);
        Assert.Equal(DecisionOutcome.Guidance, low);
    }

    [Fact]
    public void A_profile_with_an_unknown_severity_or_action_is_refused()
    {
        var profile = SignedProfileTests.Sample() with
        {
            SeverityDefaults = new Dictionary<string, string>(StringComparer.Ordinal) { ["high"] = "explode" },
        };

        Assert.Throws<FormatException>(() => SeverityActions.FromProfile(profile));
    }

    private static DecisionOutcome OutcomeOf(HookOutput output) =>
        output.Outcome?.Outcome ?? DecisionOutcomes.FromHook(output.Decision);
}
