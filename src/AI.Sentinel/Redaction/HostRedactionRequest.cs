using Microsoft.Extensions.AI;

namespace AI.Sentinel.Redaction;

/// <summary>What a host asks <see cref="SentinelPipeline.RedactAndScanAsync"/> to redact and scan.</summary>
internal sealed record HostRedactionRequest
{
    /// <summary>The request the content answers, such as a tool call's arguments. It is redacted in the scan copy
    /// only, so a value it shares with the content is judged and counted once, for the content.</summary>
    public IReadOnlyList<ChatMessage> Context { get; init; } = [];

    /// <summary>What goes toward the model, redacted in the result.</summary>
    public required IReadOnlyList<HostContent> Content { get; init; }

    /// <summary>The role the content is scanned under.</summary>
    public ChatRole ContentRole { get; init; } = ChatRole.Assistant;

    /// <summary>Content that cannot be redacted, such as an oversize block; scanned as it is.</summary>
    public IReadOnlyList<ChatMessage> Unredactable { get; init; } = [];

    /// <summary>Placeholders minted by earlier calls of the host. The scan does not flag them and the redaction
    /// leaves them as they are.</summary>
    public IReadOnlySet<string>? KnownPlaceholders { get; init; }
}
