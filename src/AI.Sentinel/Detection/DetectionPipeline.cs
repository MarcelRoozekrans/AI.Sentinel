using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;

namespace AI.Sentinel.Detection;

public sealed class DetectionPipeline
{
    private readonly IDetector[] _detectors;
    private readonly IChatClient? _escalationClient;
    private readonly ILogger<DetectionPipeline>? _logger;

    public DetectionPipeline(
        IEnumerable<IDetector> detectors,
        IChatClient? escalationClient,
        ILogger<DetectionPipeline>? logger = null)
    {
        _detectors = detectors.ToArray();
        _escalationClient = escalationClient;
        _logger = logger;
    }

    // Severity → raw score contribution (0-100 per detector)
    private static int SeverityScore(Severity s) => s switch
    {
        Severity.Critical => 100,
        Severity.High     => 70,
        Severity.Medium   => 40,
        Severity.Low      => 15,
        _                 => 0
    };

    public async ValueTask<PipelineResult> RunAsync(SentinelContext ctx, CancellationToken ct)
    {
        // Run all detectors in parallel
        var tasks = _detectors.Select(d => d.AnalyzeAsync(ctx, ct).AsTask());
        var results = await Task.WhenAll(tasks).ConfigureAwait(false);

        // LLM escalation for borderline detections (only if escalationClient configured)
        if (_escalationClient is not null)
        {
            var escalated = new List<DetectionResult>(results.Length);
            for (int i = 0; i < _detectors.Length; i++)
            {
                var r = results[i];
                if (r.Severity >= Severity.Medium && _detectors[i] is ILlmEscalatingDetector)
                {
                    var upgraded = await EscalateAsync(_detectors[i], ctx, r, _escalationClient, _logger, ct).ConfigureAwait(false);
                    escalated.Add(upgraded);
                }
                else escalated.Add(r);
            }
            results = escalated.ToArray();
        }

        var nonClean = results.Where(r => !r.IsClean).ToList();
        var scoreInputs = results.Select(r => new ThreatRiskScore(SeverityScore(r.Severity)));
        var score = ThreatRiskScore.Aggregate(scoreInputs);
        return new PipelineResult(score, nonClean);
    }

    private static async ValueTask<DetectionResult> EscalateAsync(
        IDetector detector,
        SentinelContext ctx,
        DetectionResult initial,
        IChatClient client,
        ILogger<DetectionPipeline>? logger,
        CancellationToken ct)
    {
        // IMPORTANT: Do NOT include initial.Reason here — it contains text derived from user input
        // and could be used for secondary prompt injection against the escalation LLM.
        var instruction = new ChatMessage(ChatRole.System,
            $$"""
            You are a security classifier. A rule-based detector (rule ID: {{detector.Id}}) flagged incoming content at severity {{initial.Severity}}.
            Your task: assess whether the content justifies {{initial.Severity}} severity or should be lower.
            Respond with JSON only, no explanation: {"severity":"None|Low|Medium|High|Critical","reason":"one sentence"}
            """);

        // Untrusted content is isolated in a separate user message
        var contentMessage = new ChatMessage(ChatRole.User,
            ctx.Messages.LastOrDefault()?.Text ?? "(empty)");

        try
        {
            var response = await client.GetResponseAsync(
                new List<ChatMessage> { instruction, contentMessage },
                cancellationToken: ct).ConfigureAwait(false);

            var text = response.Text ?? "";
            if (text.Contains("\"Critical\"", StringComparison.OrdinalIgnoreCase) ||
                text.Contains("Critical", StringComparison.Ordinal))
                return DetectionResult.WithSeverity(detector.Id, Severity.Critical,
                    $"LLM escalated to Critical");
            if (text.Contains("\"High\"", StringComparison.OrdinalIgnoreCase))
                return DetectionResult.WithSeverity(detector.Id, Severity.High,
                    $"LLM escalated to High");
            if (text.Contains("\"Medium\"", StringComparison.OrdinalIgnoreCase))
                return DetectionResult.WithSeverity(detector.Id, Severity.Medium,
                    $"LLM escalated to Medium");

            // LLM says None/Low or returned unexpected format — trust the rule-based result
        }
        catch (Exception ex)
        {
            // Escalation failure is non-fatal — preserve rule-based result
            logger?.LogDebug(ex, "LLM escalation failed for detector {DetectorId}", detector.Id);
        }

        return initial;
    }
}
