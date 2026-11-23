using System.Text.Json;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.ClaudeCode.Cli;
using AI.Sentinel.Copilot;
using AI.Sentinel.Copilot.Cli;
using AI.Sentinel.Detection;
using Xunit;

namespace AI.Sentinel.Tests.ClaudeCode;

public class CliOutcomeMappingTests
{
    private static OutcomeDecision D(string outcome, string reason = "why") =>
        new(Enum.Parse<DecisionOutcome>(outcome), reason, ["bundle-a"], "v1", "resident");

    private static string Claude(HookEvent evt, HookOutput output, bool headless = false)
    {
        var wire = ClaudeCodeWireOutput.From(evt, ClaudeCodeWireOutput.Resolve(output, evt, headless));
        return wire is null ? "<nothing>" : JsonSerializer.Serialize(wire, ClaudeCodeWireJsonContext.Default.ClaudeCodeWireOutput);
    }

    // --- severity actions (Task 2) -------------------------------------------------------------

    [Theory]
    [InlineData(HookDecision.Block, "Deny")]
    [InlineData(HookDecision.Warn, "Guidance")]
    [InlineData(HookDecision.Allow, "Defer")]
    public void SeverityAction_MapsToItsOutcome_AndKeepsItsEffect(HookDecision action, string outcome)
    {
        var config = new HookConfig { OnCritical = action, OnHigh = action, OnMedium = action, OnLow = action };

        foreach (var severity in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low })
        {
            Assert.Equal(Enum.Parse<DecisionOutcome>(outcome), HookSeverityMapper.MapOutcome(severity, config));
            Assert.Equal(action, HookSeverityMapper.Map(severity, config));
        }
    }

    [Fact]
    public void EnvironmentVariables_KeepTheirValuesAndEffect()
    {
        var config = HookConfig.FromEnvironment(new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["SENTINEL_HOOK_ON_HIGH"] = "Warn",
            ["SENTINEL_HOOK_ON_LOW"] = "Block",
        });

        Assert.Equal(DecisionOutcome.Guidance, HookSeverityMapper.MapOutcome(Severity.High, config));
        Assert.Equal(DecisionOutcome.Deny, HookSeverityMapper.MapOutcome(Severity.Low, config));
        Assert.Equal(DecisionOutcome.Deny, HookSeverityMapper.MapOutcome(Severity.Critical, config));
    }

    [Fact]
    public void SeverityAction_WithoutAnOutcome_KeepsTodaysClaudeCodeOutput()
    {
        Assert.Equal("{}", Claude(HookEvent.PreToolUse, new HookOutput { Decision = HookDecision.Allow }));
        Assert.Equal("""{"systemMessage":"AI.Sentinel: r"}""",
            Claude(HookEvent.PreToolUse, new HookOutput { Decision = HookDecision.Warn, Reason = "r" }));
        Assert.Equal("<nothing>", Claude(HookEvent.PreToolUse, new HookOutput { Decision = HookDecision.Block, Reason = "r" }));
    }

    // --- Claude Code --------------------------------------------------------------------------

    [Theory]
    [InlineData("Allow")]
    [InlineData("Defer")]
    public void ClaudeCode_AllowAndDefer_EmitNoPermissionDecision(string outcome)
    {
        var json = Claude(HookEvent.PreToolUse, D(outcome).ToHookOutput(canAsk: true));

        Assert.Equal("{}", json);
        Assert.DoesNotContain("permissionDecision", json, StringComparison.Ordinal);
    }

    [Fact]
    public void ClaudeCode_Guidance_AllowsTheCallAndPassesContext()
    {
        var output = D("Guidance", "use the staging key").ToHookOutput(canAsk: true);

        Assert.Equal(
            """{"hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":"use the staging key"}}""",
            Claude(HookEvent.PreToolUse, output));
        Assert.Equal(
            """{"hookSpecificOutput":{"hookEventName":"UserPromptSubmit","additionalContext":"use the staging key"}}""",
            Claude(HookEvent.UserPromptSubmit, output));
        Assert.Equal(HookDecision.Warn, output.Decision);
    }

    [Fact]
    public void ClaudeCode_GuidanceOnPostToolUse_KeepsTheRedactedOutputAndNamesTheRedactedTypes()
    {
        var output = D("Guidance", "careful").ToHookOutput(canAsk: true) with
        {
            UpdatedToolOutput = JsonSerializer.SerializeToElement("a [EMAIL_1_k3f9x2] b"),
            Redactions = new Dictionary<string, int>(StringComparer.Ordinal) { ["EMAIL"] = 1 },
        };

        var json = Claude(HookEvent.PostToolUse, output);

        Assert.Contains("\"updatedToolOutput\":\"a [EMAIL_1_k3f9x2] b\"", json, StringComparison.Ordinal);
        Assert.Contains("careful\\nAI.Sentinel redacted 1 EMAIL in this tool output", json, StringComparison.Ordinal);
    }

    [Fact]
    public void ClaudeCode_Ask_UsesThePermissionAskOnPreToolUse()
    {
        var json = Claude(HookEvent.PreToolUse, D("Ask", "pushes to main").ToHookOutput(canAsk: true));

        Assert.Equal(
            """{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"pushes to main"}}""",
            json);
    }

    [Theory]
    [InlineData(HookEvent.PreToolUse, true)]
    [InlineData(HookEvent.UserPromptSubmit, false)]
    [InlineData(HookEvent.PostToolUse, false)]
    public void ClaudeCode_AskWhereItCannotAsk_BecomesADenyWithInstructions(HookEvent evt, bool headless)
    {
        var resolved = ClaudeCodeWireOutput.Resolve(D("Ask", "pushes to main").ToHookOutput(canAsk: true), evt, headless);

        Assert.Equal(HookDecision.Block, resolved.Decision);
        Assert.Equal(DecisionOutcome.Deny, resolved.Outcome!.Outcome);
        Assert.Contains("pushes to main", resolved.Reason, StringComparison.Ordinal);
        Assert.Contains("Explain to the developer what the command does and why it is needed", resolved.Reason, StringComparison.Ordinal);
        Assert.Contains("ask a policy owner to allow it", resolved.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain("permissionDecision", Claude(evt, resolved), StringComparison.Ordinal);
    }

    [Fact]
    public void ClaudeCode_DenyOnPreToolUse_WritesNothing_SoExitTwoCarriesIt()
    {
        Assert.Equal("<nothing>", Claude(HookEvent.PreToolUse, D("Deny", "no").ToHookOutput(canAsk: true)));
    }

    [Fact]
    public void ClaudeCode_Headless_IsTheDontAskModeOrTheSetting()
    {
        var config = new HookConfig();

        Assert.False(ClaudeCodeWireOutput.IsHeadless(new HookInput(), config));
        Assert.False(ClaudeCodeWireOutput.IsHeadless(new HookInput { PermissionMode = "default" }, config));
        Assert.True(ClaudeCodeWireOutput.IsHeadless(new HookInput { PermissionMode = "dontAsk" }, config));
        Assert.True(ClaudeCodeWireOutput.IsHeadless(new HookInput(), HookConfig.FromEnvironment(
            new Dictionary<string, string?>(StringComparer.Ordinal) { ["SENTINEL_HOOK_HEADLESS"] = "on" })));
    }

    [Fact]
    public void ClaudeCode_PermissionModePayload_Deserializes()
    {
        var input = JsonSerializer.Deserialize(
            """{"session_id":"s","permission_mode":"dontAsk","tool_name":"Bash"}""", HookJsonContext.Default.HookInput);

        Assert.Equal("dontAsk", input!.PermissionMode);
    }

    // --- Copilot CLI --------------------------------------------------------------------------

    private static CopilotHookResult Copilot(HookOutput output, CopilotHookEvent evt = CopilotHookEvent.PreToolUse) =>
        CopilotWireOutput.Resolve(evt, new CopilotHookResult(output, null));

    [Fact]
    public void Copilot_Ask_BecomesADenyWithInstructions_OnEveryEvent()
    {
        var result = Copilot(D("Ask", "pushes to main").ToHookOutput(canAsk: true));

        Assert.Equal(HookDecision.Block, result.Output.Decision);
        Assert.Contains("Explain to the developer what the command does and why it is needed", result.Output.Reason, StringComparison.Ordinal);
        var wire = CopilotWireOutput.From(CopilotHookEvent.PreToolUse, result);
        Assert.Equal(HookDecision.Block, wire.Decision);
    }

    [Theory]
    [InlineData("Allow")]
    [InlineData("Defer")]
    public void Copilot_AllowAndDefer_AreAllow_WithNoPermissionDecision(string outcome)
    {
        var result = Copilot(D(outcome).ToHookOutput(canAsk: false));
        var json = JsonSerializer.Serialize(
            CopilotWireOutput.From(CopilotHookEvent.PreToolUse, result), CopilotWireJsonContext.Default.CopilotWireOutput);

        Assert.Equal(HookDecision.Allow, result.Output.Decision);
        Assert.DoesNotContain("permissionDecision", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Copilot_Guidance_BehavesAsWarnDoesToday()
    {
        var result = Copilot(D("Guidance", "careful").ToHookOutput(canAsk: false));
        var json = JsonSerializer.Serialize(
            CopilotWireOutput.From(CopilotHookEvent.PreToolUse, result), CopilotWireJsonContext.Default.CopilotWireOutput);

        Assert.Equal(HookDecision.Warn, result.Output.Decision);
        Assert.Contains("\"decision\":\"Warn\"", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("careful", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Copilot_ResultWithoutAnOutcome_IsLeftAlone()
    {
        var original = new CopilotHookResult(new HookOutput { Decision = HookDecision.Warn, Reason = "r" }, null);

        Assert.Same(original, CopilotWireOutput.Resolve(CopilotHookEvent.PostToolUse, original));
    }

    [Fact]
    public void Copilot_AskOnPostToolUse_WithholdsTheResult_SinceExitZeroKeepsNothingBack()
    {
        var result = Copilot(D("Ask", "pushes to main").ToHookOutput(canAsk: true), CopilotHookEvent.PostToolUse);
        var wire = CopilotWireOutput.From(CopilotHookEvent.PostToolUse, result);

        Assert.Equal(HookDecision.Block, wire.Decision);
        Assert.NotNull(wire.ModifiedResult);
        Assert.StartsWith("withheld by AI.Sentinel: ", wire.ModifiedResult!.TextResultForLlm, StringComparison.Ordinal);
        Assert.Contains("pushes to main", wire.ModifiedResult.TextResultForLlm, StringComparison.Ordinal);
    }

    [Fact]
    public void Copilot_AskOnUserPromptTransformed_WithholdsThePrompt()
    {
        var result = Copilot(D("Ask", "pushes to main").ToHookOutput(canAsk: true), CopilotHookEvent.UserPromptTransformed);
        var wire = CopilotWireOutput.From(CopilotHookEvent.UserPromptTransformed, result);

        Assert.Equal(HookDecision.Block, wire.Decision);
        Assert.StartsWith("withheld by AI.Sentinel: ", wire.ModifiedTransformedPrompt, StringComparison.Ordinal);
        Assert.Contains("pushes to main", wire.ModifiedTransformedPrompt, StringComparison.Ordinal);
    }

    [Fact]
    public void Copilot_AskOnPreToolUse_NeedsNoReplacement_SinceExitTwoBlocks()
    {
        var result = Copilot(D("Ask").ToHookOutput(canAsk: true), CopilotHookEvent.PreToolUse);
        var wire = CopilotWireOutput.From(CopilotHookEvent.PreToolUse, result);

        Assert.Null(wire.ModifiedResult);
        Assert.Null(wire.ModifiedTransformedPrompt);
    }

    // --- decision names and the audit summary --------------------------------------------------

    [Theory]
    [InlineData("Deny", "deny")]
    [InlineData("Ask", "ask")]
    [InlineData("Guidance", "guidance")]
    [InlineData("Allow", "allow")]
    [InlineData("Defer", "defer")]
    public void OutcomeName_IsLowerCase_AndStartsTheAuditSummary(string outcome, string name)
    {
        var parsed = Enum.Parse<DecisionOutcome>(outcome);

        Assert.Equal(name, DecisionOutcomes.Name(parsed));
        Assert.StartsWith(name + ": why;", D(outcome).Summary(), StringComparison.Ordinal);
    }
}
