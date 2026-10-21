using AI.Sentinel.ClaudeCode;

namespace AI.Sentinel.Copilot;

/// <summary>What the Copilot hook CLI writes: the adapter's <see cref="HookOutput"/> and, for
/// <see cref="CopilotHookEvent.UserPromptTransformed"/>, the prompt the model should receive instead. That prompt is the
/// redacted prompt, or on a block the withheld text; <see langword="null"/> when the prompt is delivered as it is.</summary>
internal sealed record CopilotHookResult(HookOutput Output, string? ModifiedTransformedPrompt);
