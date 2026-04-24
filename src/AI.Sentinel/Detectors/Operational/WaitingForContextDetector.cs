using System.Text.RegularExpressions;
using Microsoft.Extensions.AI;
using AI.Sentinel.Detection;
using AI.Sentinel.Domain;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Detectors.Operational;

[Singleton(As = typeof(IDetector), AllowMultiple = true)]
public sealed partial class WaitingForContextDetector : IDetector
{
    private static readonly DetectorId _id    = new("OPS-10");
    private static readonly DetectionResult _clean = DetectionResult.Clean(_id);
    private const int MinUserMessageLength = 50;

    public DetectorId Id => _id;
    public DetectorCategory Category => DetectorCategory.Operational;

    [GeneratedRegex(
        @"(please\s+provide|could\s+you\s+clarify|could\s+you\s+share|" +
        @"i\s+need\s+more\s+information|could\s+you\s+specify|" +
        @"can\s+you\s+tell\s+me\s+more)",
        RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture | RegexOptions.Compiled,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex StallPattern();

    public ValueTask<DetectionResult> AnalyzeAsync(SentinelContext ctx, CancellationToken ct)
    {
        var userText = string.Join(" ", ctx.Messages
            .Where(m => m.Role == ChatRole.User)
            .Select(m => m.Text ?? ""));
        if (userText.Length < MinUserMessageLength)
            return ValueTask.FromResult(_clean);

        var assistantText = string.Join(" ", ctx.Messages
            .Where(m => m.Role == ChatRole.Assistant)
            .Select(m => m.Text ?? ""));

        var matches = StallPattern().Matches(assistantText);
        return matches.Count switch
        {
            0 => ValueTask.FromResult(_clean),
            1 => ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Low,
                $"Model stalling: '{matches[0].Value}'")),
            _ => ValueTask.FromResult(DetectionResult.WithSeverity(_id, Severity.Medium,
                $"Multiple stall phrases ({matches.Count}) — model waiting for context it should have")),
        };
    }
}
