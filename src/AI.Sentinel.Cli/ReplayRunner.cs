using Microsoft.Extensions.AI;
using AI.Sentinel.Detection;

namespace AI.Sentinel.Cli;

public static class ReplayRunner
{
    public const string CurrentSchemaVersion = "1";

    /// <summary>
    /// Replays <paramref name="conversation"/> through <paramref name="pipeline"/> and returns
    /// a serializable <see cref="ReplayResult"/>.
    /// </summary>
    /// <remarks>
    /// <strong>Known limitation:</strong> each <see cref="TurnResult"/> contains at most one
    /// <see cref="TurnDetection"/> — the highest-severity hit per turn. This is a consequence
    /// of <c>SentinelError.ThreatDetected</c> carrying a single <c>DetectionResult</c>. If
    /// multiple detectors fire on the same turn, only the top-severity match is reported.
    /// Future enhancement: plumb the full <c>PipelineResult</c> through a new error variant
    /// or query the audit store directly.
    /// </remarks>
    public static async Task<ReplayResult> RunAsync(
        string file,
        LoadedConversation conversation,
        SentinelPipeline pipeline,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(conversation);
        ArgumentNullException.ThrowIfNull(pipeline);

        var turnResults = new List<TurnResult>(conversation.Turns.Count);
        var maxSeverity = Severity.None;

        for (var i = 0; i < conversation.Turns.Count; i++)
        {
            var turn = conversation.Turns[i];
            var messages = new List<ChatMessage>(turn.Prompt.Count);
            for (var p = 0; p < turn.Prompt.Count; p++)
            {
                messages.Add(turn.Prompt[p]);
            }

            var callResult = await pipeline.GetResponseResultAsync(messages, null, cancellationToken)
                .ConfigureAwait(false);

            IReadOnlyList<TurnDetection> detections;
            var turnMaxSeverity = Severity.None;
            if (callResult.IsFailure && callResult.Error is SentinelError.ThreatDetected t)
            {
                detections = [new TurnDetection(
                    t.Result.DetectorId.ToString(),
                    t.Result.Severity,
                    t.Result.Reason)];
                turnMaxSeverity = t.Result.Severity;
            }
            else
            {
                detections = [];
            }

            turnResults.Add(new TurnResult(i, turnMaxSeverity, detections));
            if (turnMaxSeverity > maxSeverity) maxSeverity = turnMaxSeverity;
        }

        return new ReplayResult(
            CurrentSchemaVersion,
            file,
            conversation.Format,
            conversation.Turns.Count,
            turnResults,
            maxSeverity);
    }
}
