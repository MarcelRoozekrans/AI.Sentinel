using System.Text.Json;

namespace AI.Sentinel.ClaudeCode.Policy;

/// <summary>
/// The decision for a call that no policy decision can be made for (#673, ADR-237): closed denies with guidance, ask asks. A read
/// or a search inside the repository stays allowed in both modes, so the developer can still look at the code.
/// </summary>
internal static class FailModeGate
{
    /// <summary>The source of a decision the fail mode made.</summary>
    public const string Source = "fail-mode";

    /// <summary>The reason of a read that stays allowed.</summary>
    private const string ReadOnlyReason = "A read or search inside the repository stays allowed while no policy decision can be made.";

    /// <summary>The decision for <paramref name="input"/>, with <paramref name="context"/> saying why nothing decided it.</summary>
    public static OutcomeDecision Decide(FailModeContext context, PolicyInput input, string version = "")
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(input);
        if (IsReadOnlyInRepository(input))
        {
            return new OutcomeDecision(DecisionOutcome.Allow, ReadOnlyReason, [Source], version);
        }

        var mode = context.Asks ? "ask" : "closed";
        var next = context.NeedsSignIn
            ? "Sign in to the AI.Sentinel server, then run the call again."
            : "Check the connection to the AI.Sentinel server so the profile can refresh, or ask a policy owner for help.";
        var reason = $"AI.Sentinel could not decide this call because {context.Cause}, so no policy decision could be made and the fail mode is {mode}. {next}";
        return new OutcomeDecision(context.Asks ? DecisionOutcome.Ask : DecisionOutcome.Deny, reason, [Source], version);
    }

    /// <summary>
    /// <paramref name="output"/> combined with the fail mode when a server is configured and no usable profile is cached; as it is
    /// otherwise, and for a <see langword="null"/> context, which is how a hook without a server behaves.
    /// </summary>
    public static HookOutput ApplyMissingProfile(
        FailModeContext? context, HookOutput output, string cli, string toolName, JsonElement toolInput, string session, string? repositoryRoot)
    {
        ArgumentNullException.ThrowIfNull(output);
        if (context is not { ServerConfigured: true, ProfileUsable: false })
        {
            return output;
        }

        var input = PolicyInputBuilder.Build(cli, toolName, toolInput, session, [], repositoryRoot);
        var existing = output.Outcome ?? OutcomeDecision.FromHook(output.Decision, output.Reason, LocalPolicy.ChecksSource);
        return OutcomeDecision.Strictest([existing, Decide(context, input)]).ToHookOutput(canAsk: true);
    }

    private static bool IsReadOnlyInRepository(PolicyInput input) =>
        (string.Equals(input.Kind, ToolKind.Read.ToWire(), StringComparison.Ordinal) || string.Equals(input.Kind, ToolKind.Search.ToWire(), StringComparison.Ordinal))
        && input.Details.Paths is { Count: > 0 } paths && paths.All(p => p.InRepository);
}
