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
    private readonly Action<string>? _onDetectorFailure;

    public DetectionPipeline(
        IEnumerable<IDetector> detectors,
        IReadOnlyDictionary<Type, DetectorConfiguration>? configurations,
        IChatClient? escalationClient,
        ILogger<DetectionPipeline>? logger = null,
        Action<string>? onDetectorFailure = null)
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
        _onDetectorFailure = onDetectorFailure;
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
                vTasks[i] = SafeAnalyzeAsync(_detectors[i], ctx, ct);

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

        // Apply per-detector severity clamp (Floor/Cap) before LLM escalation,
        // so that Cap correctly suppresses escalation and Floor doesn't trigger it.
        ApplySeverityClamp(results);

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

    /// <summary>Runs one detector, degrading a failure to Clean.</summary>
    /// <remarks>
    /// A detector that reaches the network — any SemanticDetectorBase once an embedding endpoint is
    /// configured — can throw for reasons that have nothing to do with the content: the endpoint is
    /// down, the key expired, the provider rate-limited. Letting that escape aborts the whole scan,
    /// and in the hook CLIs a thrown scan exits 1, which the host treats as a tool failure rather
    /// than a block. The prompt would then proceed unscanned by <em>every</em> detector, including the
    /// rule-based ones that never needed the network. One control being unavailable must not disable
    /// the rest.
    /// </remarks>
    private async ValueTask<DetectionResult> SafeAnalyzeAsync(IDetector detector, SentinelContext ctx, CancellationToken ct)
    {
        try
        {
            return await detector.AnalyzeAsync(ctx, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // The caller asked to stop; that is not a detector fault.
            throw;
        }
        catch (Exception ex)
        {
            var message = $"AI.Sentinel: detector {detector.Id.Value} failed and was skipped for this scan ({ex.GetType().Name}: {ex.Message}). Other detectors still ran.";
            _logger?.LogWarning(ex, "AI.Sentinel: detector {DetectorId} failed and was skipped for this scan.", detector.Id.Value);
            _onDetectorFailure?.Invoke(message);
            return DetectionResult.Clean(detector.Id);
        }
    }

    private void ApplySeverityClamp(DetectionResult[] results)
    {
        for (int i = 0; i < results.Length; i++)
        {
            var cfg = _configurations[i];
            if (cfg is null || results[i].IsClean) continue;

            var clamped = results[i].Severity;
            if (cfg.SeverityFloor is { } floor && clamped < floor) clamped = floor;
            if (cfg.SeverityCap is { } cap && clamped > cap) clamped = cap;

            if (clamped != results[i].Severity)
            {
                results[i] = results[i] with { Severity = clamped };
            }
        }
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
            You are a security classifier. A rule-based detector (rule ID: {{detector.Id.Value}}) flagged incoming content at severity {{initial.Severity}}.
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
