using System.Text.Json;
using AI.Sentinel.Redaction;

namespace AI.Sentinel.ClaudeCode.ServerApprovals;

/// <summary>Redacts the tool input of an approval request with the redaction a hook applies to tool results (ADR-027), so the
/// approver sees what they approve and a secret does not leave the PC.</summary>
internal static class ApprovalArgsRedaction
{
    /// <summary>The string values of <paramref name="args"/> redacted with the redacting detectors of <paramref name="provider"/>;
    /// <see langword="null"/> when the redaction fails, and the input is then not sent.</summary>
    public static JsonElement? Redact(IServiceProvider provider, JsonElement args)
    {
        ArgumentNullException.ThrowIfNull(provider);
        var pipeline = provider.BuildSentinelPipeline(HookPipelineRunner.UnusedChatClient.Instance);
        return pipeline.TryRedactJson(args, HookPipelineRunner.PlaceholdersIn(args.GetRawText()));
    }
}
