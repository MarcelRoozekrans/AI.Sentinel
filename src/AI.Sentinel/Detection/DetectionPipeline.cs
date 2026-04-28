using System.Buffers;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;

namespace AI.Sentinel.Detection;

public sealed class DetectionPipeline : IDetectionPipeline
{
    private readonly IDetector[] _detectors;
    private readonly DetectorConfiguration?[] _configurations;
    private readonly IChatClient? _escalationClient;
    private readonly ILogger<DetectionPipeline>? _logger;

    public DetectionPipeline(
        IEnumerable<IDetector> detectors,
        IReadOnlyDictionary<Type, DetectorConfiguration>? configurations,
        IChatClient? escalationClient,
        ILogger<DetectionPipeline>? logger = null)
    {
        var enabled = new List<IDetector>();
        var enabledConfigs = new List<DetectorConfiguration?>();
        foreach (var d in detectors)
        {
            DetectorConfiguration? cfg = null;
            if (configurations is not null)
            {
                configurations.TryGetValue(d.GetType(), out cfg);
            }

            if (cfg is not null && !cfg.Enabled)
            {
                continue;  // skip disabled detector entirely — zero CPU on the hot path
            }

            enabled.Add(d);
            enabledConfigs.Add(cfg);
        }

        _detectors        = enabled.ToArray();
        _configurations   = enabledConfigs.ToArray();
        _escalationClient = escalationClient;
        _logger           = logger;
    }

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
        if (_detectors.Length == 0)
            return new PipelineResult(ThreatRiskScore.Zero, []);

        var vTasks = ArrayPool<ValueTask<DetectionResult>>.Shared.Rent(_detectors.Length);
        DetectionResult[] results;
        try
        {
            // Start all detectors
            for (int i = 0; i < _detectors.Length; i++)
                vTasks[i] = _detectors[i].AnalyzeAsync(ctx, ct);

            // Fast path: all completed synchronously (typical for rule-based detectors with cached clean results)
            if (AllCompletedSuccessfully(vTasks, _detectors.Length))
            {
                results = new DetectionResult[_detectors.Length];
                for (int i = 0; i < _detectors.Length; i++)
                    results[i] = vTasks[i].Result;
            }
            else
            {
                // Slow path: at least one async detector — use Task.WhenAll
                var tasks = new Task<DetectionResult>[_detectors.Length];
                for (int i = 0; i < _detectors.Length; i++)
                    tasks[i] = vTasks[i].AsTask();
                results = await Task.WhenAll(tasks).ConfigureAwait(false);
            }
        }
        finally
        {
            ArrayPool<ValueTask<DetectionResult>>.Shared.Return(vTasks);
        }

        // LLM escalation (unchanged logic)
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

        return BuildResult(results);
    }

    private static bool AllCompletedSuccessfully(ValueTask<DetectionResult>[] tasks, int count)
    {
        foreach (ref readonly var t in tasks.AsSpan(0, count))
            if (!t.IsCompletedSuccessfully) return false;
        return true;
    }

    private static PipelineResult BuildResult(DetectionResult[] results)
    {
        var nonClean = new List<DetectionResult>();
        var scores   = new ThreatRiskScore[results.Length];
        for (int i = 0; i < results.Length; i++)
        {
            if (!results[i].IsClean) nonClean.Add(results[i]);
            scores[i] = new ThreatRiskScore(SeverityScore(results[i].Severity));
        }
        var score = ThreatRiskScore.Aggregate(scores);
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
        var instruction = new ChatMessage(ChatRole.System,
            $$"""
            You are a security classifier. A rule-based detector (rule ID: {{detector.Id}}) flagged incoming content at severity {{initial.Severity}}.
            Your task: assess whether the content justifies {{initial.Severity}} severity or should be lower.
            Respond with JSON only, no explanation: {"severity":"None|Low|Medium|High|Critical","reason":"one sentence"}
            """);

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
                return DetectionResult.WithSeverity(detector.Id, Severity.Critical, "LLM escalated to Critical");
            if (text.Contains("\"High\"", StringComparison.OrdinalIgnoreCase))
                return DetectionResult.WithSeverity(detector.Id, Severity.High, "LLM escalated to High");
            if (text.Contains("\"Medium\"", StringComparison.OrdinalIgnoreCase))
                return DetectionResult.WithSeverity(detector.Id, Severity.Medium, "LLM escalated to Medium");
        }
        catch (Exception ex)
        {
            logger?.LogDebug(ex, "LLM escalation failed for detector {DetectorId}", detector.Id);
        }

        return initial;
    }
}
