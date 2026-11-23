namespace AI.Sentinel.ClaudeCode;

/// <summary>
/// The five outcomes a hook decision can have, strictest first: the lower the value, the stricter the outcome, so the
/// strictest of several is the smallest (ADR-234).
/// <list type="bullet">
/// <item><see cref="Deny"/> stops the call.</item>
/// <item><see cref="Ask"/> lets the developer decide, where the CLI can ask.</item>
/// <item><see cref="Guidance"/> lets the call run and gives the agent advice, where the CLI can pass context back.</item>
/// <item><see cref="Allow"/> and <see cref="Defer"/> emit no permission decision, so the CLI's own permission prompt
/// still applies. They differ only in what they say: allow is a policy that approves, defer is no opinion.</item>
/// </list>
/// </summary>
internal enum DecisionOutcome
{
    Deny = 0,
    Ask = 1,
    Guidance = 2,
    Allow = 3,
    Defer = 4,
}
