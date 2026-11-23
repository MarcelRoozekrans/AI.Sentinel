namespace AI.Sentinel.ClaudeCode.Policy.Rego;

/// <summary>
/// The rules the host adds to every policy: they combine what the bundles say into one decision, strictest first. A bundle
/// adds reasons with <c>deny contains "why" if ...</c>, and likewise <c>ask</c>, <c>guidance</c> and <c>allow</c>; a bundle sets the outcome of a finding severity with
/// <c>severity_actions contains {"severity": "high", "outcome": "guidance"}</c>; the host owns <c>outcome</c>, <c>reasons</c> and <c>decision</c>.
/// </summary>
internal static class HostRules
{
    public const string Text = """
        package sentinel

        import rego.v1

        # Host-provided: combines the outcomes of every bundle. Strictest first: deny, ask, guidance, allow, defer.

        # Declares every outcome set, so a policy that defines only some of them still compiles.
        deny contains "" if false

        ask contains "" if false

        guidance contains "" if false

        allow contains "" if false

        # Declares the severity outcomes a policy may set, such as
        # severity_actions contains {"severity": "high", "outcome": "guidance"}; the host takes the strictest per severity.
        severity_actions contains {"severity": "", "outcome": ""} if false

        default outcome := "defer"

        outcome := "deny" if count(deny) > 0

        else := "ask" if count(ask) > 0

        else := "guidance" if count(guidance) > 0

        else := "allow" if count(allow) > 0

        # Only the reasons of the winning outcome are given.
        reasons := [r | some r in deny] if outcome == "deny"

        else := [r | some r in ask] if outcome == "ask"

        else := [r | some r in guidance] if outcome == "guidance"

        else := [r | some r in allow] if outcome == "allow"

        else := []

        decision := {"outcome": outcome, "reasons": reasons, "severity_actions": severity_actions}
        """;
}
