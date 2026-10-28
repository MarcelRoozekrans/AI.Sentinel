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
    /// A turn the pipeline quarantines lists every non-clean detection of its scan, not only the one that
    /// triggered the quarantine.
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
                var all = new List<TurnDetection>(t.Detections.Count);
                foreach (var d in t.Detections)
                {
                    all.Add(new TurnDetection(d.DetectorId.Value, d.Severity, d.Reason));
                    if (d.Severity > turnMaxSeverity) turnMaxSeverity = d.Severity;
                }
                detections = all;
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
