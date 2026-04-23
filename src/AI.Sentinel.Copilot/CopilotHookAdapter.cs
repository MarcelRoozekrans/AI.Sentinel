using Microsoft.Extensions.AI;
using AI.Sentinel.ClaudeCode;

namespace AI.Sentinel.Copilot;

public sealed class CopilotHookAdapter(IServiceProvider provider, HookConfig? config = null)
{
    private readonly HookConfig _config = config ?? new HookConfig();

    public Task<HookOutput> HandleAsync(
        CopilotHookEvent evt,
        CopilotHookInput input,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(input);
        var messages = BuildMessages(evt, input);
        return HookPipelineRunner.RunAsync(provider, _config, messages, ct);
    }

    private static IReadOnlyList<ChatMessage> BuildMessages(
        CopilotHookEvent evt,
        CopilotHookInput input) => evt switch
    {
        CopilotHookEvent.UserPromptSubmitted => [new ChatMessage(ChatRole.User, input.Prompt ?? "")],
        CopilotHookEvent.PreToolUse => [new ChatMessage(ChatRole.User,
            $"tool:{input.ToolName} input:{input.ToolInput?.GetRawText() ?? ""}")],
        CopilotHookEvent.PostToolUse =>
        [
            new ChatMessage(ChatRole.User,
                $"tool:{input.ToolName} input:{input.ToolInput?.GetRawText() ?? ""}"),
            new ChatMessage(ChatRole.Assistant,
                input.ToolResponse?.GetRawText() ?? ""),
        ],
        _ => throw new ArgumentOutOfRangeException(nameof(evt)),
    };
}
