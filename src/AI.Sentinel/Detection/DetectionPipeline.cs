using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Detection;

public sealed class DetectionPipeline(
    IEnumerable<IDetector> detectors,
    IChatClient? escalationClient)
{
    private readonly IDetector[] _detectors = detectors.ToArray();

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
        var results = await Task.WhenAll(tasks);

        // LLM escalation for borderline detections (only if escalationClient configured)
        if (escalationClient is not null)
        {
            var escalated = new List<DetectionResult>(results.Length);
            for (int i = 0; i < _detectors.Length; i++)
            {
                var r = results[i];
                if (r.Severity >= Severity.Medium && _detectors[i] is ILlmEscalatingDetector)
                {
                    var upgraded = await EscalateAsync(_detectors[i], ctx, r, escalationClient, ct);
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
        CancellationToken ct)
    {
        var lastMessage = ctx.Messages.LastOrDefault()?.Text ?? "(empty)";
        var prompt = $$"""
            You are a security classifier. A rule-based detector flagged this content as {{initial.Severity}}: {{initial.Reason}}
            Content: {{lastMessage}}
            Respond with JSON only: {"severity":"None|Low|Medium|High|Critical","reason":"one sentence"}
            """;

        try
        {
            var response = await client.GetResponseAsync(
                [new ChatMessage(ChatRole.User, prompt)],
                cancellationToken: ct);

            var text = response.Text ?? "";
            if (text.Contains("Critical", StringComparison.OrdinalIgnoreCase))
                return DetectionResult.WithSeverity(detector.Id, Severity.Critical, $"LLM escalated: {text[..Math.Min(100, text.Length)]}");
            if (text.Contains("High", StringComparison.OrdinalIgnoreCase))
                return DetectionResult.WithSeverity(detector.Id, Severity.High, $"LLM escalated: {text[..Math.Min(100, text.Length)]}");
            if (text.Contains("Medium", StringComparison.OrdinalIgnoreCase))
                return DetectionResult.WithSeverity(detector.Id, Severity.Medium, $"LLM escalated: {text[..Math.Min(100, text.Length)]}");
        }
        catch
        {
            // Escalation failure is non-fatal — fall back to rule-based result
        }

        return initial;
    }
}
