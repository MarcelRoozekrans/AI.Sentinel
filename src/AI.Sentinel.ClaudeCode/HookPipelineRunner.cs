using System.Text.Json;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using AI.Sentinel.Redaction;

namespace AI.Sentinel.ClaudeCode;

/// <summary>
/// Vendor-agnostic pipeline runner for hook adapters. Takes the mapped
/// <see cref="ChatMessage"/> list, runs it through AI.Sentinel prompt-only, with no inner
/// LLM call, and returns a <see cref="HookOutput"/>.
/// </summary>
/// <remarks>
/// Each detection gets its own decision. One whose action is Quarantine maps through <see cref="HookConfig"/>
/// by severity. One whose action is Alert surfaces as Warn, or as Allow when HookConfig maps its severity to
/// Allow. One whose action is Log or PassThrough gives Allow. The hook answers the most restrictive of these
/// decisions, and its reason names the detection behind it, the higher severity on a tie.
/// <para>
/// Public so that other vendor adapters (e.g. <c>AI.Sentinel.Copilot</c>)
/// can call it after doing their own payload -> messages mapping.
/// </para>
/// </remarks>
public static class HookPipelineRunner
{
    /// <summary>Scans <paramref name="messages"/> prompt-only and maps the result to a hook decision.</summary>
    /// <param name="provider">Service provider with AI.Sentinel registered.</param>
    /// <param name="config">Severity-to-decision mapping and verbosity.</param>
    /// <param name="messages">The messages mapped from the hook payload.</param>
    /// <param name="sessionId">The raw session id string from the hook input, recorded on the audit entries.
    /// <see langword="null"/>, empty or whitespace means none, and a fresh id is minted for the call.
    /// The pipeline itself takes the <see cref="SessionId"/> domain type; this method converts.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Allow when nothing was detected, otherwise the most restrictive per-detection decision.</returns>
    public static async Task<HookOutput> RunAsync(
        IServiceProvider provider,
        HookConfig config,
        IReadOnlyList<ChatMessage> messages,
        string? sessionId,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(messages);

        // Build a pipeline bound to an unused inner client — a prompt-only scan
        // never invokes it, so the client shape is irrelevant. This scan returns every
        // detection with its action, so the hook decides per detection.
        var pipeline = provider.BuildSentinelPipeline(UnusedChatClient.Instance);
        var findings = await pipeline.ScanMessagesForFindingsAsync(
            messages, string.IsNullOrWhiteSpace(sessionId) ? null : new SessionId(sessionId), ct).ConfigureAwait(false);

        // A clean scan, or one refused by the rate limit, allows. Hook invocations don't
        // honor rate limits (they're not real LLM calls), so the latter is unreachable in practice.
        return Decide(findings, config);
    }

    /// <summary>The start of the body that replaces a tool output the hook blocks; the block reason follows it.</summary>
    private const string WithheldPrefix = "withheld by AI.Sentinel: ";

    /// <summary>The text that replaces a tool output or a prompt the hook blocks: <c>withheld by AI.Sentinel: </c>
    /// followed by <paramref name="reason"/>.</summary>
    internal static string WithheldText(string? reason) => WithheldPrefix + reason;

    /// <summary>
    /// Redacts a tool result on its way to the model and scans the redacted copy, with <paramref name="context"/>, the
    /// tool call, redacted in the scan copy only.
    /// </summary>
    /// <remarks>
    /// The result is redacted in its string values only, so its keys, numbers and nesting stay as they are. The
    /// decision follows <see cref="Decide"/>.
    /// <list type="bullet">
    /// <item>A Block withholds the output: <see cref="HookOutput.UpdatedToolOutput"/> is <see cref="WithheldOutput"/>
    /// of the result, and nothing is recorded as redacted, because nothing is delivered.</item>
    /// <item>Otherwise, when anything was redacted, <see cref="HookOutput.UpdatedToolOutput"/> is the redacted result,
    /// <see cref="HookOutput.Redactions"/> its counts, and the redactions are audited as <c>REDACTED</c>.</item>
    /// <item>A clean result, or a redaction that fell back to the unredacted scan, leaves both null.</item>
    /// </list>
    /// A hook process keeps no placeholder store, so placeholder-shaped tokens already in the tool call or the result,
    /// such as one an earlier redaction put there, are passed as known placeholders: they are neither flagged nor
    /// wrapped again.
    /// </remarks>
    internal static async Task<HookOutput> RunToolResultAsync(
        IServiceProvider provider,
        HookConfig config,
        IReadOnlyList<ChatMessage> context,
        JsonElement toolResult,
        string? sessionId,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(context);

        var pipeline = provider.BuildSentinelPipeline(UnusedChatClient.Instance);
        var request = new HostRedactionRequest
        {
            Context = context,
            Content = [HostContent.FromJson(toolResult)],
            ContentRole = ChatRole.Assistant,
            KnownPlaceholders = CollectPlaceholders(context, toolResult),
        };
        var result = await pipeline.RedactAndScanAsync(
            request, string.IsNullOrWhiteSpace(sessionId) ? null : new SessionId(sessionId), ct).ConfigureAwait(false);

        var output = Decide(result.Findings, config);
        if (output.Decision == HookDecision.Block)
        {
            return output with { UpdatedToolOutput = WithheldOutput(toolResult, output.Reason) };
        }

        if (!result.Redacted)
        {
            return output;
        }

        await pipeline.AppendRedactionsAsync(result, result.SessionId, ct).ConfigureAwait(false);
        return output with { UpdatedToolOutput = result.Content[0].Json, Redactions = result.RedactedByType };
    }

    /// <summary>
    /// Redacts a user prompt on its way to the model and scans the redacted copy, for a host that lets the hook replace
    /// the prompt the model receives.
    /// </summary>
    /// <remarks>
    /// The decision follows <see cref="Decide"/>.
    /// <list type="bullet">
    /// <item>A Block withholds the prompt: the rewritten prompt is <see cref="WithheldText"/> of the reason, and
    /// nothing is recorded as redacted, because nothing is delivered.</item>
    /// <item>Otherwise, when anything was redacted, the rewritten prompt is the redacted prompt, and the redactions are
    /// audited as <c>REDACTED</c>.</item>
    /// <item>A clean prompt, or a redaction that fell back to the unredacted scan, gives <see langword="null"/>: the
    /// prompt is delivered as it is.</item>
    /// </list>
    /// Placeholder-shaped tokens already in the prompt are passed as known placeholders, as for a tool result.
    /// </remarks>
    internal static async Task<(HookOutput Output, string? Rewritten)> RunPromptAsync(
        IServiceProvider provider,
        HookConfig config,
        string prompt,
        string? sessionId,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(prompt);

        var pipeline = provider.BuildSentinelPipeline(UnusedChatClient.Instance);
        HashSet<string>? known = null;
        CollectPlaceholderTokens(prompt, ref known);
        var request = new HostRedactionRequest
        {
            Content = [HostContent.FromText(prompt)],
            ContentRole = ChatRole.User,
            KnownPlaceholders = known,
        };
        var result = await pipeline.RedactAndScanAsync(
            request, string.IsNullOrWhiteSpace(sessionId) ? null : new SessionId(sessionId), ct).ConfigureAwait(false);

        var output = Decide(result.Findings, config);
        if (output.Decision == HookDecision.Block)
        {
            return (output, WithheldText(output.Reason));
        }

        if (!result.Redacted)
        {
            return (output, null);
        }

        await pipeline.AppendRedactionsAsync(result, result.SessionId, ct).ConfigureAwait(false);
        return (output, result.Content[0].Text);
    }

    /// <summary>
    /// The body that replaces a tool output the hook blocks: <paramref name="toolResponse"/> with every non-empty string
    /// value replaced by <see cref="WithheldText"/> of <paramref name="reason"/>, and its names, numbers, booleans,
    /// nulls and nesting kept. Claude Code ignores a replacement that does not match a built-in tool's output schema and
    /// shows the original instead, so the shape is kept, and so is an identifier-like string value of every property named
    /// <c>type</c>, a discriminator such as Read's <c>"type":"text"</c>. Empty strings stay empty, so a field such as Bash's empty
    /// <c>stderr</c> does not repeat the notice. A string, an absent response or a null gives the withheld text itself.
    /// </summary>
    internal static JsonElement WithheldOutput(JsonElement toolResponse, string? reason)
    {
        var text = WithheldText(reason);
        if (toolResponse.ValueKind is not (JsonValueKind.Object or JsonValueKind.Array))
        {
            return JsonString(text);
        }

        var buffer = new System.Buffers.ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            WriteWithheld(toolResponse, text, writer);
        }

        using var doc = JsonDocument.Parse(buffer.WrittenMemory);
        return doc.RootElement.Clone();
    }

    /// <summary>True when <paramref name="value"/> looks like an identifier, <c>^[A-Za-z][A-Za-z0-9_.-]{0,31}$</c>,
    /// such as <c>text</c>: the only <c>type</c> values a withheld body keeps.</summary>
    internal static bool IsDiscriminator(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 32 || !char.IsAsciiLetter(value[0]))
        {
            return false;
        }

        foreach (var c in value.AsSpan(1))
        {
            if (!char.IsAsciiLetterOrDigit(c) && c is not ('_' or '.' or '-'))
            {
                return false;
            }
        }

        return true;
    }

    private static void WriteWithheld(JsonElement element, string text, Utf8JsonWriter writer)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in element.EnumerateObject())
                {
                    writer.WritePropertyName(property.Name);
                    if (property.Value.ValueKind == JsonValueKind.String
                        && string.Equals(property.Name, "type", StringComparison.Ordinal)
                        && IsDiscriminator(property.Value.GetString()))
                    {
                        // A discriminator such as Read's "type":"text"; Claude Code rejects the body without it. Only an
                        // identifier-like string is kept, so free text placed under "type" cannot get past the walk.
                        property.Value.WriteTo(writer);
                    }
                    else
                    {
                        WriteWithheld(property.Value, text, writer);
                    }
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                {
                    WriteWithheld(item, text, writer);
                }
                writer.WriteEndArray();
                break;
            case JsonValueKind.String:
                // An empty string, such as Bash's empty stderr, stays empty so the notice appears once.
                writer.WriteStringValue(element.ValueEquals(string.Empty) ? string.Empty : text);
                break;
            default:
                // Numbers, booleans and null hold no text.
                element.WriteTo(writer);
                break;
        }
    }

    /// <summary>A JSON string element holding <paramref name="text"/>, built without reflection.</summary>
    internal static JsonElement JsonString(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var buffer = new System.Buffers.ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStringValue(text);
        }

        using var doc = JsonDocument.Parse(buffer.WrittenMemory);
        return doc.RootElement.Clone();
    }

    /// <summary>The placeholder-shaped tokens in the tool call and the result; null when there are none.</summary>
    private static HashSet<string>? CollectPlaceholders(IReadOnlyList<ChatMessage> context, JsonElement toolResult)
    {
        HashSet<string>? known = null;
        foreach (var message in context)
        {
            CollectPlaceholderTokens(message.Text, ref known);
        }

        CollectPlaceholderTokens(toolResult.GetRawText(), ref known);
        return known;
    }

    /// <summary>Adds the placeholder-shaped tokens in <paramref name="text"/> to <paramref name="known"/>, creating it
    /// on the first one.</summary>
    private static void CollectPlaceholderTokens(string? text, ref HashSet<string>? known)
    {
        if (string.IsNullOrEmpty(text) || text.IndexOf('[', StringComparison.Ordinal) < 0)
        {
            return;
        }

        foreach (var match in PlaceholderFormat.Pattern().EnumerateMatches(text))
        {
            known ??= new HashSet<string>(StringComparer.Ordinal);
            known.Add(text.Substring(match.Index, match.Length));
        }
    }

    /// <summary>
    /// The most restrictive per-detection decision, and on a tie the higher severity for the reason. Deciding per
    /// detection, rather than mapping the most restrictive action's representative, keeps an Alert, such as a
    /// compliance finding in the hook CLIs, from being lost when it co-fires with a Quarantine detection whose
    /// severity HookConfig maps to Allow.
    /// </summary>
    internal static HookOutput Decide(IReadOnlyList<ScanFinding> findings, HookConfig config)
    {
        DetectionResult? reason = null;
        var decision = HookDecision.Allow;
        foreach (var finding in findings)
        {
            if (DecisionFor(finding, config) is not { } candidate) continue;
            if (reason is null || candidate > decision
                || (candidate == decision && finding.Detection.Severity > reason.Severity))
            {
                decision = candidate;
                reason = finding.Detection;
            }
        }

        return reason is null
            ? new HookOutput { Decision = HookDecision.Allow }
            : new HookOutput { Decision = decision, Reason = $"{reason.DetectorId.Value} {reason.Severity}: {reason.Reason}" };
    }

    /// <summary>
    /// Quarantine maps through <see cref="HookConfig"/> by severity. Alert warns, but never overrides an operator who
    /// mapped its severity to Allow. Log and PassThrough allow without a reason, so they return
    /// <see langword="null"/>.
    /// </summary>
    private static HookDecision? DecisionFor(ScanFinding finding, HookConfig config)
    {
        var mapped = HookSeverityMapper.Map(finding.Detection.Severity, config);
        return finding.Action switch
        {
            SentinelAction.Quarantine => mapped,
            SentinelAction.Alert => mapped < HookDecision.Warn ? mapped : HookDecision.Warn,
            _ => null,
        };
    }

    // IChatClient satisfying BuildSentinelPipeline's signature. Never invoked.
    private sealed class UnusedChatClient : IChatClient
    {
        public static readonly UnusedChatClient Instance = new();
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("UnusedChatClient should never be invoked — hook adapters use prompt-only scanning.");
        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("UnusedChatClient should never be invoked — hook adapters use prompt-only scanning.");
        public object? GetService(Type serviceType, object? key = null) => null;
        public void Dispose() { }
    }
}
