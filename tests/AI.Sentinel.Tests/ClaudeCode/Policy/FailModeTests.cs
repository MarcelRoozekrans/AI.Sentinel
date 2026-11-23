using System.Text.Json;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.ClaudeCode.Policy;
using AI.Sentinel.ClaudeCode.Policy.Rego;
using AI.Sentinel.ClaudeCode.Resident;
using AI.Sentinel.Profiles;
using AI.Sentinel.Tests.ClaudeCode.Resident;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode.Policy;

/// <summary>What the hook does when no policy decision can be made (#673): the fail mode of the profile decides, closed by default
/// and ask when the node chose it. Nothing here reads a server setting, because sign-in and the pinned keys come with #659: the hook
/// is handed a <see cref="FailModeContext"/>, and without one it behaves as before.</summary>
public class FailModeTests
{
    private const string Root = "/work/repo";
    private static readonly HookOutput Allowed = new() { Decision = HookDecision.Allow };

    private static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement;

    private static FakePolicyEvaluator Silent() => new(OutcomeDecision.Resident, () => null);

    private static FakePolicyEvaluator Failing() => new(OutcomeDecision.InProcess, () => throw new InvalidOperationException("the policy aborted: secret-in-the-input"));

    private static LocalPolicy Policy(FailModeContext? failMode, params IPolicyEvaluator[] evaluators) =>
        LocalPolicy.ForEvaluators("v1", ["org-baseline", "team-guidance"], Root, evaluators, failMode);

    private static FailModeContext Profile(string failMode) =>
        FailModeContext.From(ProfileVerification.Accepted(new PolicyProfile
        {
            Organisation = "acme",
            Repository = "github.com/acme/app",
            Node = "n",
            ConfigurationVersion = 1,
            ModuleHash = "h",
            Module = "m",
            FailMode = failMode,
            SeverityDefaults = new Dictionary<string, string>(StringComparer.Ordinal),
            LoggingSwitches = new Dictionary<string, bool>(StringComparer.Ordinal),
            IssuedAt = DateTimeOffset.UnixEpoch,
            ExpiresAt = DateTimeOffset.UnixEpoch.AddDays(1),
        }));

    [Fact]
    public void With_fail_mode_closed_a_call_no_place_could_decide_is_denied_with_the_reason_and_what_to_do()
    {
        using var policy = Policy(Profile(ProfileFailModes.Closed), Silent(), Silent());

        var output = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"ls"}"""), "s");

        Assert.Equal(HookDecision.Block, output.Decision);
        Assert.Equal(DecisionOutcome.Deny, output.Outcome!.Outcome);
        Assert.Contains("no policy decision could be made", output.Reason, StringComparison.Ordinal);
        Assert.Contains("fail mode is closed", output.Reason, StringComparison.Ordinal);
        Assert.Contains("policy owner", output.Reason, StringComparison.Ordinal);
        Assert.Equal([FailModeGate.Source], output.Outcome.Sources);
    }

    [Fact]
    public void With_fail_mode_ask_the_same_call_asks_and_each_cli_maps_the_ask_as_for_any_other()
    {
        using var policy = Policy(Profile(ProfileFailModes.Ask), Silent());

        var output = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"ls"}"""), "s");

        Assert.Equal(DecisionOutcome.Ask, output.Outcome!.Outcome);
        Assert.Equal(HookDecision.Warn, output.Decision);
        var headless = output.Outcome.ToHookOutput(canAsk: false);
        Assert.Equal(HookDecision.Block, headless.Decision);
        Assert.Contains("cannot ask", headless.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void An_expired_profile_still_decides_with_its_own_fail_mode_and_says_it_expired()
    {
        var expired = FailModeContext.From(ProfileVerification.Rejected(ProfileRejection.Expired, ProfileFailModes.Ask));
        using var policy = Policy(expired, Silent());

        var output = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"ls"}"""), "s");

        Assert.Equal(DecisionOutcome.Ask, output.Outcome!.Outcome);
        Assert.Contains("expired", output.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void A_profile_that_cannot_be_used_for_another_reason_has_no_fail_mode_to_read_so_closed_applies()
    {
        var forged = FailModeContext.From(ProfileVerification.Rejected(ProfileRejection.BadSignature));
        using var policy = Policy(forged, Silent());

        var output = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"ls"}"""), "s");

        Assert.Equal(DecisionOutcome.Deny, output.Outcome!.Outcome);
    }

    [Fact]
    public void A_policy_that_answers_is_not_touched_by_the_fail_mode()
    {
        using var policy = Policy(Profile(ProfileFailModes.Closed), new FakePolicyEvaluator(OutcomeDecision.Resident, () => FakePolicyEvaluator.Deny("recursive delete")));

        var output = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"rm -rf x"}"""), "s");

        Assert.Equal("recursive delete", output.Reason);
        Assert.Equal(OutcomeDecision.Resident, output.Outcome!.DecidedAt);
    }

    [Fact]
    public void Without_a_fail_mode_context_no_decision_is_an_error_as_before()
    {
        using var policy = Policy(failMode: null, Silent());

        Assert.Throws<InvalidOperationException>(() => policy.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"ls"}"""), "s"));
    }

    [Fact]
    public void An_internal_error_in_the_hook_is_not_a_fail_mode_matter_and_still_fails_closed()
    {
        using var policy = Policy(Profile(ProfileFailModes.Ask), Silent());

        // No tool name: the hook cannot build the input. This throws whatever the fail mode, and the CLI blocks on it.
        Assert.Throws<ArgumentNullException>(() => policy.Decide(Allowed, PolicyClis.ClaudeCode, null!, Json("{}"), "s"));
    }

    [Theory]
    [InlineData(ProfileFailModes.Closed)]
    [InlineData(ProfileFailModes.Ask)]
    public void A_bundle_that_errors_at_runtime_denies_and_names_the_bundle_whatever_the_fail_mode(string failMode)
    {
        using var policy = Policy(Profile(failMode), Failing());

        var output = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"ls"}"""), "s");

        Assert.Equal(DecisionOutcome.Deny, output.Outcome!.Outcome);
        Assert.Contains("org-baseline", output.Reason, StringComparison.Ordinal);
        Assert.Contains("team-guidance", output.Reason, StringComparison.Ordinal);
        Assert.Equal(["policy:org-baseline,team-guidance"], output.Outcome.Sources);
        Assert.DoesNotContain("secret-in-the-input", output.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(ProfileFailModes.Closed)]
    [InlineData(ProfileFailModes.Ask)]
    public void A_bundle_that_errors_while_the_severities_are_read_denies_by_name_instead_of_throwing(string failMode)
    {
        using var policy = Policy(Profile(failMode), Failing());

        var severities = policy.Severities();
        var output = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"ls"}"""), "s");

        Assert.Same(SeverityActions.None, severities);
        Assert.Equal(DecisionOutcome.Deny, output.Outcome!.Outcome);
        Assert.Contains("org-baseline", output.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-in-the-input", output.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Without_a_fail_mode_a_bundle_that_errors_while_the_severities_are_read_still_throws()
    {
        using var policy = Policy(null, Failing());

        Assert.Throws<InvalidOperationException>(() => policy.Severities());
    }

    [Theory]
    [InlineData(ProfileFailModes.Closed)]
    [InlineData(ProfileFailModes.Ask)]
    public void Read_and_search_inside_the_repository_stay_allowed_when_no_decision_can_be_made(string failMode)
    {
        using var policy = Policy(Profile(failMode), Silent());

        var read = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Read", Json("""{"file_path":"/work/repo/src/a.cs"}"""), "s");
        var search = policy.Decide(Allowed, PolicyClis.ClaudeCode, "Grep", Json("""{"path":"/work/repo/src"}"""), "s");

        Assert.Equal(DecisionOutcome.Allow, read.Outcome!.Outcome);
        Assert.Equal(DecisionOutcome.Allow, search.Outcome!.Outcome);
    }

    [Theory]
    [InlineData("Read", """{"file_path":"/etc/passwd"}""")]
    [InlineData("Read", """{"file_path":"/work/repo/../other/a.cs"}""")]
    [InlineData("Read", "{}")]
    [InlineData("Write", """{"file_path":"/work/repo/a.cs"}""")]
    [InlineData("Bash", """{"command":"cat /work/repo/a.cs"}""")]
    public void Anything_else_is_not_exempt(string tool, string input)
    {
        using var policy = Policy(Profile(ProfileFailModes.Closed), Silent());

        var output = policy.Decide(Allowed, PolicyClis.ClaudeCode, tool, Json(input), "s");

        Assert.Equal(DecisionOutcome.Deny, output.Outcome!.Outcome);
    }

    [Fact]
    public void An_in_repository_read_does_not_loosen_what_the_other_checks_decided()
    {
        using var policy = Policy(Profile(ProfileFailModes.Closed), Silent());
        var blocked = new HookOutput { Decision = HookDecision.Block, Reason = "critical finding" };

        var output = policy.Decide(blocked, PolicyClis.ClaudeCode, "Read", Json("""{"file_path":"/work/repo/a.cs"}"""), "s");

        Assert.Equal(HookDecision.Block, output.Decision);
        Assert.Equal("critical finding", output.Reason);
    }

    // The call of a hook that has a server configured but no profile: nothing decides it but the fail mode (sign-in is #659).

    [Fact]
    public void With_a_server_configured_and_no_profile_the_hook_uses_closed_and_tells_the_developer_to_sign_in()
    {
        var output = FailModeGate.ApplyMissingProfile(
            FailModeContext.NotSignedIn, Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"ls"}"""), "s", Root);

        Assert.Equal(HookDecision.Block, output.Decision);
        Assert.Contains("sign in", output.Reason, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(DecisionOutcome.Deny, output.Outcome!.Outcome);
    }

    [Fact]
    public void With_no_server_configured_there_is_no_profile_to_miss_and_the_output_is_untouched()
    {
        var output = FailModeGate.ApplyMissingProfile(
            FailModeContext.NoServer, Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"ls"}"""), "s", Root);

        Assert.Same(Allowed, output);
        Assert.Same(Allowed, FailModeGate.ApplyMissingProfile(null, Allowed, PolicyClis.ClaudeCode, "Bash", Json("{}"), "s", Root));
    }

    [Fact]
    public void A_usable_profile_means_the_gate_leaves_the_call_to_the_policy()
    {
        var output = FailModeGate.ApplyMissingProfile(
            Profile(ProfileFailModes.Closed), Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"ls"}"""), "s", Root);

        Assert.Same(Allowed, output);
    }

    [Fact]
    public void Without_a_profile_a_read_inside_the_repository_stays_allowed_and_an_expired_profile_with_ask_asks()
    {
        var read = FailModeGate.ApplyMissingProfile(
            FailModeContext.NotSignedIn, Allowed, PolicyClis.ClaudeCode, "Read", Json("""{"file_path":"/work/repo/a.cs"}"""), "s", Root);
        var expired = FailModeGate.ApplyMissingProfile(
            FailModeContext.From(ProfileVerification.Rejected(ProfileRejection.Expired, ProfileFailModes.Ask)),
            Allowed, PolicyClis.ClaudeCode, "Bash", Json("""{"command":"ls"}"""), "s", Root);

        Assert.Equal(DecisionOutcome.Allow, read.Outcome!.Outcome);
        Assert.Equal(DecisionOutcome.Ask, expired.Outcome!.Outcome);
    }
}
