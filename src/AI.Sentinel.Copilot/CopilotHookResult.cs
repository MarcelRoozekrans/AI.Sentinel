using AI.Sentinel.ClaudeCode;

namespace AI.Sentinel.Copilot;

/// <summary>What the Copilot hook CLI writes: the adapter's <see cref="HookOutput"/> and, for
/// <see cref="CopilotHookEvent.UserPromptTransformed"/>, the prompt the model should receive instead. That prompt is the
/// redacted prompt, or on a block the withheld text; <see langword="null"/> when the prompt is delivered as it is.
/// <see cref="ToolResultType"/> is the <c>resultType</c> of the original tool result on
/// <see cref="CopilotHookEvent.PostToolUse"/>, kept so a replaced result still tells the model how the tool ended;
/// <see langword="null"/> when there is none or it is not identifier-like.</summary>
internal sealed record CopilotHookResult(HookOutput Output, string? ModifiedTransformedPrompt, string? ToolResultType = null);
