using System.Text;
using System.Text.Json;
using Microsoft.Extensions.AI;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;
using ZeroAlloc.Serialisation;

namespace AI.Sentinel.Detectors.Security;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed class OutputSchemaDetector(
    SentinelOptions options,
    ISerializerDispatcher? dispatcher = null) : IDetector
{
    private static readonly DetectorId _id = new("SEC-29");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Security;

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        if (options.ExpectedResponseType is not Type expected || dispatcher is null)
            return ValueTask.FromResult(_clean);

        string? responseText = null;
        for (var i = ctx.Messages.Count - 1; i >= 0; i--)
        {
            if (ctx.Messages[i].Role == ChatRole.Assistant && ctx.Messages[i].Text is { Length: > 0 } t)
            {
                responseText = t;
                break;
            }
        }
        if (responseText is null) return ValueTask.FromResult(_clean);

        var jsonText = ExtractJson(responseText);
        var bytes = Encoding.UTF8.GetBytes(jsonText);

        try
        {
            var deserialized = dispatcher.Deserialize(bytes, expected);
            if (deserialized is null)
                return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.High,
                    $"Response deserialized to null for type {expected.Name}"));
            return ValueTask.FromResult(_clean);
        }
        catch (JsonException ex)
        {
            return ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.High,
                $"Response failed schema validation for {expected.Name}: {ex.Message}"));
        }
        catch (NotSupportedException)
        {
            // Type not registered with the dispatcher — caller misconfiguration, not a threat.
            return ValueTask.FromResult(_clean);
        }
    }

    private static string ExtractJson(string text)
    {
        var trimmed = text.AsSpan().Trim();
        if (!trimmed.StartsWith("```".AsSpan(), StringComparison.Ordinal)) return text;

        var afterFence = trimmed[3..];
        var newline = afterFence.IndexOf('\n');
        if (newline < 0) return text;

        var body = afterFence[(newline + 1)..];
        var closing = body.LastIndexOf("```".AsSpan(), StringComparison.Ordinal);
        return closing < 0 ? text : body[..closing].ToString();
    }
}
