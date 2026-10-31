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

    /// <summary>The indexes of <see cref="Content"/> items that are redacted but not scanned, because they repeat
    /// another item the scan judges, such as an MCP tool result's structured content that its text block mirrors.
    /// The same content is then judged, and counted against <see cref="SentinelOptions.MaxScanBytes"/>, once. Null
    /// scans every item.</summary>
    public IReadOnlySet<int>? UnscannedContent { get; init; }

    /// <summary>Content that cannot be redacted, such as an oversize block; scanned as it is.</summary>
    public IReadOnlyList<ChatMessage> Unredactable { get; init; } = [];

    /// <summary>Placeholders minted by earlier calls of the host. The scan does not flag them and the redaction
    /// leaves them as they are.</summary>
    public IReadOnlySet<string>? KnownPlaceholders { get; init; }
}
