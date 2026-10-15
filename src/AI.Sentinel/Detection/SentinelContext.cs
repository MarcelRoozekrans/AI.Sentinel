using AI.Sentinel.Audit;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Detection;

public sealed class SentinelContext(
    AgentId SenderId,
    AgentId ReceiverId,
    SessionId SessionId,
    IReadOnlyList<ChatMessage> Messages,
    IReadOnlyList<AuditEntry> History,
    string? LlmId = null,
    string? systemPrompt = null)
{
    public AgentId SenderId { get; } = SenderId;
    public AgentId ReceiverId { get; } = ReceiverId;
    public SessionId SessionId { get; } = SessionId;
    public IReadOnlyList<ChatMessage> Messages { get; } = Messages;
    public IReadOnlyList<AuditEntry> History { get; } = History;
    public string? LlmId { get; } = LlmId;

    /// <summary>The conversation's system prompt, when one was supplied.</summary>
    /// <remarks>
    /// Carried on both scan legs so a detector can compare the model's output against it. The
    /// response leg scans only the generated message, so without this the prompt is unavailable
    /// exactly where a leak would appear.
    /// </remarks>
    public string? SystemPrompt { get; } = systemPrompt;

    private static readonly IReadOnlySet<string> NoPlaceholders = new HashSet<string>(StringComparer.Ordinal);

    /// <summary>
    /// The redaction placeholders, such as <c>[API_KEY_1_k3f9x2]</c>, that the current call minted when it redacted
    /// the request, plus those minted by every enclosing Sentinel call in its parent chain, when this call runs
    /// below another one. A redacting detector does not flag them as a value: they are what a redacted request
    /// looks like. Empty by default, so a surface that never redacts exempts nothing, and text that merely
    /// looks like a placeholder is judged like any other text.
    /// </summary>
    public IReadOnlySet<string> RedactionPlaceholders { get; init; } = NoPlaceholders;

    /// <summary>
    /// Every placeholder-shaped token in the redacted request the model was sent, for the response scan.
    /// Only a detector listed in <see cref="RedactingDetectorIds"/> may treat them as exempt: that detector
    /// redacted the request, so a token still sitting where its value would be was minted or judged not a value.
    /// For any other detector, such a token may be a real secret that reached the model as it was.
    /// </summary>
    public IReadOnlySet<string> RequestPlaceholders { get; init; } = NoPlaceholders;

    /// <summary>Ids of the detectors that redacted the request of this call.</summary>
    public IReadOnlySet<string> RedactingDetectorIds { get; init; } = NoPlaceholders;

    /// <summary>
    /// The placeholders <paramref name="detector"/> must not flag as a value: <see cref="RedactionPlaceholders"/>,
    /// plus <see cref="RequestPlaceholders"/> when that detector redacted this call's request.
    /// </summary>
    public IReadOnlySet<string> PlaceholdersExemptFor(DetectorId detector)
    {
        ArgumentNullException.ThrowIfNull(detector);
        if (RequestPlaceholders.Count == 0 || !RedactingDetectorIds.Contains(detector.Value))
        {
            return RedactionPlaceholders;
        }

        var exempt = new HashSet<string>(RedactionPlaceholders, StringComparer.Ordinal);
        exempt.UnionWith(RequestPlaceholders);
        return exempt;
    }

    private string? _textContent;

    /// <summary>
    /// The concatenated text of all messages (non-text content parts are omitted), joined by a single space.
    /// Computed once and cached per context — detectors that join with a space separator should use this instead of string.Join.
    /// </summary>
    public string TextContent =>
        _textContent ??= string.Join(" ", Messages.Select(m => m.Text ?? ""));
}
