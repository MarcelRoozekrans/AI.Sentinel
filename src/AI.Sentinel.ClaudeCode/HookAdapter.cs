using Microsoft.Extensions.AI;

namespace AI.Sentinel.ClaudeCode;

public sealed class HookAdapter(IServiceProvider provider, HookConfig? config = null)
{
    private readonly HookConfig _config = config ?? new HookConfig();

    public Task<HookOutput> HandleAsync(HookEvent evt, HookInput input, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(input);
        var messages = BuildMessages(evt, input);
        return HookPipelineRunner.RunAsync(provider, _config, messages, ct);
    }

    private static IReadOnlyList<ChatMessage> BuildMessages(HookEvent evt, HookInput input) => evt switch
    {
        HookEvent.UserPromptSubmit => [new ChatMessage(ChatRole.User, input.Prompt ?? "")],
        HookEvent.PreToolUse => [new ChatMessage(ChatRole.User,
            $"tool:{input.ToolName} input:{input.ToolInput?.GetRawText() ?? ""}")],
        HookEvent.PostToolUse =>
        [
            new ChatMessage(ChatRole.User,
                $"tool:{input.ToolName} input:{input.ToolInput?.GetRawText() ?? ""}"),
            new ChatMessage(ChatRole.Assistant,
                input.ToolResponse?.GetRawText() ?? ""),
        ],
        _ => throw new ArgumentOutOfRangeException(nameof(evt)),
    };
}
