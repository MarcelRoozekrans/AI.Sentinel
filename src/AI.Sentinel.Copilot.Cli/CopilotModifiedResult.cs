namespace AI.Sentinel.Copilot.Cli;

/// <summary>The tool result Copilot gives the model instead of the original: <c>{"resultType":"success",
/// "textResultForLlm":"..."}</c>.</summary>
internal sealed record CopilotModifiedResult(string ResultType, string TextResultForLlm);
